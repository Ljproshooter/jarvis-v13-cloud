-- LJ AI Stripe Billing hardening (additive and safe to rerun).
-- Run this in Supabase SQL Editor before enabling the Stripe webhook.
-- Only the cloud service_role can call these state-changing RPCs.
begin;

alter table public.lj_subscriptions
  add column if not exists stripe_price_id text,
  add column if not exists currency text,
  add column if not exists checkout_session_id text,
  add column if not exists latest_invoice_id text,
  add column if not exists cancel_at_period_end boolean not null default false,
  add column if not exists canceled_at timestamptz,
  add column if not exists ended_at timestamptz,
  add column if not exists last_stripe_event_created bigint not null default 0,
  add column if not exists last_reconcile_sequence bigint not null default 0,
  add column if not exists checkout_lock_token text,
  add column if not exists checkout_lock_expires_at timestamptz,
  add column if not exists created_at timestamptz not null default now();

update public.lj_subscriptions
set stripe_customer_id = nullif(btrim(stripe_customer_id), ''),
    stripe_subscription_id = nullif(btrim(stripe_subscription_id), ''),
    stripe_price_id = nullif(btrim(stripe_price_id), ''),
    checkout_session_id = nullif(btrim(checkout_session_id), ''),
    currency = nullif(upper(btrim(currency)), ''),
    checkout_lock_token = null,
    checkout_lock_expires_at = null;

create unique index if not exists lj_subscription_customer_idx
  on public.lj_subscriptions(stripe_customer_id)
  where stripe_customer_id is not null;

create unique index if not exists lj_subscription_stripe_subscription_idx
  on public.lj_subscriptions(stripe_subscription_id)
  where stripe_subscription_id is not null;

create unique index if not exists lj_subscription_checkout_idx
  on public.lj_subscriptions(checkout_session_id)
  where checkout_session_id is not null;

-- The apps receive a real Supabase user token for authentication. Even if a
-- future profiles RLS policy permits users to edit ordinary profile fields,
-- they must never be able to self-assign ADMIN/VIP or extend an expiry date.
create or replace function public.protect_lj_profile_entitlements()
returns trigger
language plpgsql
security invoker
set search_path = public, pg_temp
as $$
begin
  if current_user not in ('postgres', 'supabase_admin', 'service_role') then
    if tg_op = 'INSERT'
       and (
         upper(coalesce(new.role, 'USER')) <> 'USER'
         or upper(coalesce(new.plan, 'FREE')) <> 'FREE'
         or new.plan_expires_at is not null
       ) then
      raise exception 'New LJ AI profiles cannot assign a role or paid plan';
    elsif tg_op = 'UPDATE'
       and (
         new.role is distinct from old.role
         or new.plan is distinct from old.plan
         or new.plan_expires_at is distinct from old.plan_expires_at
       ) then
      raise exception 'LJ AI role and plan fields are server managed';
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists protect_lj_profile_entitlements_update on public.profiles;
create trigger protect_lj_profile_entitlements_update
before insert or update on public.profiles
for each row execute function public.protect_lj_profile_entitlements();

alter table public.billing_webhook_events
  add column if not exists status text not null default 'processed',
  add column if not exists attempts integer not null default 1,
  add column if not exists last_error text,
  add column if not exists stripe_created_at bigint not null default 0,
  add column if not exists updated_at timestamptz not null default now();

alter table public.billing_webhook_events
  alter column processed_at drop not null,
  alter column processed_at drop default;

update public.billing_webhook_events
set status = 'processed',
    attempts = greatest(attempts, 1),
    updated_at = coalesce(updated_at, processed_at, now())
where status is null or status not in ('processing', 'processed', 'failed');

create sequence if not exists public.lj_billing_reconcile_sequence;

-- Serialize the Stripe retrieve + entitlement sync for each Subscription. A
-- sequence alone cannot order two workers if the older snapshot is fetched
-- after a newer snapshot. The lease makes the entire observation atomic from
-- the application's point of view; an expired worker also cannot commit once
-- a replacement worker has claimed a newer sequence.
create table if not exists public.lj_billing_reconcile_locks (
  subscription_id text primary key
    check (subscription_id ~ '^sub_[A-Za-z0-9]+$'),
  lock_token text not null
    check (lock_token ~ '^[0-9a-f]{64}$'),
  reconcile_sequence bigint not null check (reconcile_sequence > 0),
  expires_at timestamptz not null,
  updated_at timestamptz not null default now()
);

alter table public.lj_billing_reconcile_locks enable row level security;
revoke all on table public.lj_billing_reconcile_locks
  from public, anon, authenticated, service_role;

-- An event ID is either newly CLAIMED, already PROCESSED, or currently BUSY.
-- Failed/stale claims can be retried without acknowledging a failed mutation as
-- complete, and two Render workers cannot process the same event concurrently.
create or replace function public.claim_lj_billing_webhook_event_v2(
  p_event_id text,
  p_event_type text,
  p_stripe_created_at bigint default 0
) returns text
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  event_status text;
begin
  if coalesce(btrim(p_event_id), '') = '' or coalesce(btrim(p_event_type), '') = '' then
    raise exception 'Stripe event identity is required';
  end if;

  insert into public.billing_webhook_events(
    event_id, event_type, status, attempts, last_error,
    stripe_created_at, processed_at, updated_at
  ) values (
    p_event_id, p_event_type, 'processing', 1, null,
    greatest(coalesce(p_stripe_created_at, 0), 0), null, now()
  ) on conflict(event_id) do nothing;

  if found then
    return 'CLAIMED';
  end if;

  select status into event_status
    from public.billing_webhook_events
   where event_id = p_event_id
   for update;

  if event_status = 'processed' then
    return 'PROCESSED';
  end if;

  update public.billing_webhook_events
     set status = 'processing',
         attempts = attempts + 1,
         last_error = null,
         event_type = p_event_type,
         stripe_created_at = greatest(stripe_created_at, coalesce(p_stripe_created_at, 0)),
         processed_at = null,
         updated_at = now()
   where event_id = p_event_id
     and (
       status = 'failed'
       or (status = 'processing' and updated_at < now() - interval '5 minutes')
     );

  if found then
    return 'CLAIMED';
  end if;
  return 'BUSY';
end;
$$;

create or replace function public.complete_lj_billing_webhook_event(
  p_event_id text
) returns void
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  update public.billing_webhook_events
     set status = 'processed', processed_at = now(), last_error = null, updated_at = now()
   where event_id = p_event_id and status = 'processing';
end;
$$;

create or replace function public.fail_lj_billing_webhook_event(
  p_event_id text,
  p_error text
) returns void
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  update public.billing_webhook_events
     set status = 'failed', processed_at = null,
         last_error = left(coalesce(p_error, 'billing event failed'), 500),
         updated_at = now()
   where event_id = p_event_id and status = 'processing';
end;
$$;

-- Kept as an internal primitive for migration compatibility. New application
-- code obtains its sequence only through claim_lj_billing_reconcile_lease.
create or replace function public.next_lj_billing_reconcile_sequence()
returns bigint
language sql
security definer
set search_path = public, pg_temp
as $$
  select nextval('public.lj_billing_reconcile_sequence'::regclass);
$$;

create or replace function public.claim_lj_billing_reconcile_lease(
  p_subscription_id text,
  p_lock_token text
) returns table(acquired boolean, reconcile_sequence bigint)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  lock_row public.lj_billing_reconcile_locks%rowtype;
begin
  if coalesce(p_subscription_id, '') !~ '^sub_[A-Za-z0-9]+$'
     or coalesce(p_lock_token, '') !~ '^[0-9a-f]{64}$' then
    raise exception 'Invalid billing reconciliation lease request';
  end if;

  insert into public.lj_billing_reconcile_locks(
    subscription_id, lock_token, reconcile_sequence, expires_at, updated_at
  ) values (
    p_subscription_id,
    p_lock_token,
    nextval('public.lj_billing_reconcile_sequence'::regclass),
    now() + interval '3 minutes',
    now()
  ) on conflict(subscription_id) do nothing
  returning * into lock_row;

  if found then
    return query select true, lock_row.reconcile_sequence;
    return;
  end if;

  select * into lock_row
    from public.lj_billing_reconcile_locks
   where subscription_id = p_subscription_id
   for update;

  if lock_row.expires_at <= now() then
    update public.lj_billing_reconcile_locks
       set lock_token = p_lock_token,
           reconcile_sequence = nextval('public.lj_billing_reconcile_sequence'::regclass),
           expires_at = now() + interval '3 minutes',
           updated_at = now()
     where subscription_id = p_subscription_id
    returning * into lock_row;
    return query select true, lock_row.reconcile_sequence;
    return;
  end if;

  return query select false, 0::bigint;
end;
$$;

create or replace function public.finish_lj_billing_reconcile_lease(
  p_subscription_id text,
  p_lock_token text
) returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if coalesce(p_subscription_id, '') !~ '^sub_[A-Za-z0-9]+$'
     or coalesce(p_lock_token, '') !~ '^[0-9a-f]{64}$' then
    return false;
  end if;
  delete from public.lj_billing_reconcile_locks
   where subscription_id = p_subscription_id
     and lock_token = p_lock_token;
  return found;
end;
$$;

-- A short per-user lease prevents double clicks/concurrent devices from
-- creating separate payable Checkout Sessions. Stripe idempotency is a second
-- layer; this database lease is the first.
create or replace function public.claim_lj_checkout_lease(
  p_user_id uuid,
  p_lock_token text
) returns table(
  acquired boolean,
  stripe_customer_id text,
  stripe_subscription_id text,
  checkout_session_id text,
  status text,
  current_period_end timestamptz,
  plan_key text,
  billing_period text,
  stripe_price_id text,
  currency text
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  subscription_row public.lj_subscriptions%rowtype;
begin
  if p_user_id is null or coalesce(p_lock_token, '') !~ '^[0-9a-f]{64}$' then
    raise exception 'Invalid checkout lease request';
  end if;

  select * into subscription_row
    from public.lj_subscriptions
   where user_id = p_user_id
   for update;
  if not found then
    raise exception 'LJ AI billing profile does not exist';
  end if;

  if subscription_row.checkout_lock_token is not null
     and subscription_row.checkout_lock_token <> p_lock_token
     and subscription_row.checkout_lock_expires_at > now() then
    return query select false,
      subscription_row.stripe_customer_id,
      subscription_row.stripe_subscription_id,
      subscription_row.checkout_session_id,
      subscription_row.status,
      subscription_row.current_period_end,
      subscription_row.plan_key,
      subscription_row.billing_period,
      subscription_row.stripe_price_id,
      subscription_row.currency;
    return;
  end if;

  update public.lj_subscriptions
     set checkout_lock_token = p_lock_token,
         checkout_lock_expires_at = now() + interval '3 minutes',
         updated_at = now()
   where user_id = p_user_id
  returning * into subscription_row;

  return query select true,
    subscription_row.stripe_customer_id,
    subscription_row.stripe_subscription_id,
    subscription_row.checkout_session_id,
    subscription_row.status,
    subscription_row.current_period_end,
    subscription_row.plan_key,
    subscription_row.billing_period,
    subscription_row.stripe_price_id,
    subscription_row.currency;
end;
$$;

create or replace function public.finish_lj_checkout_lease(
  p_user_id uuid,
  p_lock_token text,
  p_checkout_session_id text default null
) returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if p_checkout_session_id is not null and p_checkout_session_id !~ '^cs_' then
    raise exception 'Invalid Stripe Checkout Session ID';
  end if;
  update public.lj_subscriptions
     set checkout_session_id = coalesce(p_checkout_session_id, checkout_session_id),
         checkout_lock_token = null,
         checkout_lock_expires_at = null,
         updated_at = now()
   where user_id = p_user_id
     and checkout_lock_token = p_lock_token;
  return found;
end;
$$;

-- Apply one server-validated Stripe Subscription snapshot. The application
-- maps Price ID -> plan before calling this RPC. The monotonic reconcile value
-- prevents a slower, older observation from overwriting a newer one.
create or replace function public.sync_lj_stripe_subscription_v2(
  p_user_id uuid,
  p_plan_key text,
  p_billing_period text,
  p_status text,
  p_customer_id text,
  p_subscription_id text,
  p_price_id text,
  p_currency text,
  p_period_start timestamptz,
  p_period_end timestamptz,
  p_cancel_at_period_end boolean,
  p_canceled_at timestamptz,
  p_ended_at timestamptz,
  p_latest_invoice_id text,
  p_event_created bigint,
  p_reconcile_sequence bigint
) returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  current_row public.lj_subscriptions%rowtype;
  profile_role text;
  normalised_plan text := upper(coalesce(p_plan_key, ''));
  normalised_period text := upper(coalesce(p_billing_period, ''));
  normalised_status text := lower(coalesce(p_status, 'unknown'));
  normalised_currency text := upper(coalesce(p_currency, 'USD'));
  event_created bigint := greatest(coalesce(p_event_created, 0), 0);
  is_entitled boolean;
begin
  if normalised_plan not in ('BASIC', 'PREMIUM', 'VIP') then
    raise exception 'Invalid LJ AI Stripe plan';
  end if;
  if normalised_period not in ('MONTHLY', '3_MONTHS', 'YEARLY') then
    raise exception 'Invalid LJ AI Stripe billing period';
  end if;
  if normalised_currency !~ '^[A-Z]{3}$' then
    raise exception 'Invalid Stripe currency';
  end if;
  if coalesce(btrim(p_customer_id), '') = ''
     or coalesce(btrim(p_subscription_id), '') = ''
     or coalesce(btrim(p_price_id), '') = '' then
    raise exception 'Stripe customer, subscription, and Price IDs are required';
  end if;
  if coalesce(p_reconcile_sequence, 0) <= 0 then
    raise exception 'A billing reconciliation sequence is required';
  end if;
  if not exists(
    select 1
      from public.lj_billing_reconcile_locks
     where subscription_id = p_subscription_id
       and reconcile_sequence = p_reconcile_sequence
       and expires_at > now()
  ) then
    raise exception 'An active billing reconciliation lease is required';
  end if;

  select upper(coalesce(role, 'USER')) into profile_role
    from public.profiles
   where id = p_user_id
   for update;
  if not found then
    raise exception 'LJ AI profile does not exist';
  end if;
  if profile_role = 'ADMIN' then
    return false;
  end if;

  if exists(
    select 1 from public.lj_subscriptions
     where stripe_customer_id = p_customer_id and user_id <> p_user_id
  ) then
    raise exception 'Stripe customer is already linked to another user';
  end if;
  if exists(
    select 1 from public.lj_subscriptions
     where stripe_subscription_id = p_subscription_id and user_id <> p_user_id
  ) then
    raise exception 'Stripe subscription is already linked to another user';
  end if;

  select * into current_row
    from public.lj_subscriptions
   where user_id = p_user_id
   for update;

  if found and current_row.last_reconcile_sequence >= p_reconcile_sequence then
    return false;
  end if;

  -- Never let an event from a second/old Subscription replace an existing
  -- nonterminal Subscription. Checkout and the portal must resolve it first.
  if found
     and current_row.stripe_subscription_id is not null
     and current_row.stripe_subscription_id <> p_subscription_id
     and lower(coalesce(current_row.status, '')) not in ('', 'free', 'canceled', 'incomplete_expired') then
    return false;
  end if;

  is_entitled := normalised_status in ('active', 'trialing')
                   and p_period_end is not null
                   and p_period_end > now();

  insert into public.lj_subscriptions(
    user_id, plan_key, billing_period, status,
    stripe_customer_id, stripe_subscription_id, stripe_price_id, currency,
    current_period_start, current_period_end, latest_invoice_id,
    cancel_at_period_end, canceled_at, ended_at,
    last_stripe_event_created, last_reconcile_sequence,
    checkout_session_id, checkout_lock_token, checkout_lock_expires_at, updated_at
  ) values (
    p_user_id, normalised_plan, normalised_period, normalised_status,
    p_customer_id, p_subscription_id, p_price_id, normalised_currency,
    p_period_start, p_period_end, p_latest_invoice_id,
    coalesce(p_cancel_at_period_end, false), p_canceled_at, p_ended_at,
    event_created, p_reconcile_sequence,
    null, null, null, now()
  ) on conflict(user_id) do update set
    plan_key = excluded.plan_key,
    billing_period = excluded.billing_period,
    status = excluded.status,
    stripe_customer_id = excluded.stripe_customer_id,
    stripe_subscription_id = excluded.stripe_subscription_id,
    stripe_price_id = excluded.stripe_price_id,
    currency = excluded.currency,
    current_period_start = excluded.current_period_start,
    current_period_end = excluded.current_period_end,
    latest_invoice_id = excluded.latest_invoice_id,
    cancel_at_period_end = excluded.cancel_at_period_end,
    canceled_at = excluded.canceled_at,
    ended_at = excluded.ended_at,
    last_stripe_event_created = greatest(
      public.lj_subscriptions.last_stripe_event_created,
      excluded.last_stripe_event_created
    ),
    last_reconcile_sequence = excluded.last_reconcile_sequence,
    checkout_session_id = null,
    checkout_lock_token = null,
    checkout_lock_expires_at = null,
    updated_at = now();

  update public.profiles
     set plan = case when is_entitled then normalised_plan else 'FREE' end,
         plan_expires_at = p_period_end
   where id = p_user_id
     and upper(coalesce(role, 'USER')) <> 'ADMIN';

  return true;
end;
$$;

-- Remove grants from older draft overloads before granting only the hardened
-- service-role entry points.
do $$
declare
  function_row record;
begin
  for function_row in
    select p.oid::regprocedure as signature
      from pg_proc p
      join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'public'
       and p.proname = any(array[
         'claim_lj_billing_webhook_event',
         'claim_lj_billing_webhook_event_v2',
         'complete_lj_billing_webhook_event',
         'fail_lj_billing_webhook_event',
         'next_lj_billing_reconcile_sequence',
         'claim_lj_billing_reconcile_lease',
         'finish_lj_billing_reconcile_lease',
         'claim_lj_checkout_lease',
         'finish_lj_checkout_lease',
         'sync_lj_stripe_subscription',
         'sync_lj_stripe_subscription_v2',
         'protect_lj_profile_entitlements'
       ])
  loop
    execute format(
      'revoke all on function %s from public, anon, authenticated, service_role',
      function_row.signature
    );
  end loop;
end;
$$;

grant execute on function public.claim_lj_billing_webhook_event_v2(text, text, bigint)
  to service_role;
grant execute on function public.complete_lj_billing_webhook_event(text)
  to service_role;
grant execute on function public.fail_lj_billing_webhook_event(text, text)
  to service_role;
grant execute on function public.claim_lj_billing_reconcile_lease(text, text)
  to service_role;
grant execute on function public.finish_lj_billing_reconcile_lease(text, text)
  to service_role;
grant execute on function public.claim_lj_checkout_lease(uuid, text)
  to service_role;
grant execute on function public.finish_lj_checkout_lease(uuid, text, text)
  to service_role;
grant execute on function public.sync_lj_stripe_subscription_v2(
  uuid, text, text, text, text, text, text, text,
  timestamptz, timestamptz, boolean, timestamptz, timestamptz,
  text, bigint, bigint
) to service_role;

-- Trigger execution does not require a client grant. Keep the entitlement
-- guard itself unavailable as an RPC.
revoke all on function public.protect_lj_profile_entitlements()
  from public, anon, authenticated, service_role;

commit;
