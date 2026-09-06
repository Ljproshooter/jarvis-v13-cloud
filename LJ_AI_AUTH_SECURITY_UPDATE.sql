-- LJ AI V15.9.5 additive verified-email and recovery security migration.
-- Run once in Supabase SQL Editor before deploying the matching cloud code.
begin;

create table if not exists public.lj_auth_email_proofs (
    user_id uuid primary key references auth.users(id) on delete cascade,
    email_hash text not null check (email_hash ~ '^[0-9a-f]{64}$'),
    proof_source text not null check (proof_source in ('SIGNUP_CONFIRMATION', 'LEGACY_REVERIFICATION')),
    initiated_at timestamptz not null default now(),
    challenge_expires_at timestamptz not null,
    verified_at timestamptz,
    evidence_at timestamptz,
    proof_session_id uuid,
    invalidated_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    check (challenge_expires_at > initiated_at),
    check (verified_at is null or evidence_at is not null)
);

create index if not exists lj_auth_email_proofs_verified_idx
    on public.lj_auth_email_proofs(user_id, email_hash)
    where verified_at is not null and invalidated_at is null;

create table if not exists public.lj_auth_recovery_challenges (
    user_id uuid primary key references auth.users(id) on delete cascade,
    challenge_id uuid not null default gen_random_uuid(),
    email_hash text not null check (email_hash ~ '^[0-9a-f]{64}$'),
    requested_at timestamptz not null default now(),
    expires_at timestamptz not null,
    claimed_session_id uuid,
    claim_expires_at timestamptz,
    consumed_at timestamptz,
    updated_at timestamptz not null default now(),
    check (expires_at > requested_at)
);

-- These ALTER statements make the additive migration safe to rerun if an
-- earlier release created the recovery table before challenge generations
-- were introduced.
alter table public.lj_auth_recovery_challenges
    add column if not exists challenge_id uuid;
update public.lj_auth_recovery_challenges
   set challenge_id = gen_random_uuid()
 where challenge_id is null;
alter table public.lj_auth_recovery_challenges
    alter column challenge_id set default gen_random_uuid(),
    alter column challenge_id set not null;
create unique index if not exists lj_auth_recovery_challenge_id_idx
    on public.lj_auth_recovery_challenges(challenge_id);

-- A recovery Auth session is single-use across all challenge generations.
-- Recording it at claim time prevents an ambiguous/failed external password
-- update from letting the same session claim a later generation.
create table if not exists public.lj_auth_recovery_session_uses (
    session_id uuid primary key,
    user_id uuid not null references auth.users(id) on delete cascade,
    challenge_id uuid not null,
    claimed_at timestamptz not null default now()
);

alter table public.lj_auth_email_proofs enable row level security;
alter table public.lj_auth_recovery_challenges enable row level security;
alter table public.lj_auth_recovery_session_uses enable row level security;
revoke all on public.lj_auth_email_proofs from public, anon, authenticated;
revoke all on public.lj_auth_recovery_challenges from public, anon, authenticated;
revoke all on public.lj_auth_recovery_session_uses from public, anon, authenticated;
grant select, insert, update, delete on public.lj_auth_email_proofs to service_role;
grant select, insert, update, delete on public.lj_auth_recovery_challenges to service_role;
grant select, insert, update, delete on public.lj_auth_recovery_session_uses to service_role;

create or replace function public.begin_lj_email_proof(
    p_user_id uuid,
    p_email_hash text,
    p_source text,
    p_ttl_seconds integer
) returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    existing public.lj_auth_email_proofs%rowtype;
    bounded_ttl integer;
begin
    if coalesce(auth.role(), '') <> 'service_role' then
        raise exception 'service role required';
    end if;
    if p_email_hash !~ '^[0-9a-f]{64}$'
       or p_source not in ('SIGNUP_CONFIRMATION', 'LEGACY_REVERIFICATION') then
        return false;
    end if;
    if not exists (select 1 from auth.users where id = p_user_id) then
        return false;
    end if;
    bounded_ttl := case
        when p_source = 'SIGNUP_CONFIRMATION' then least(greatest(p_ttl_seconds, 300), 86400)
        else least(greatest(p_ttl_seconds, 300), 3600)
    end;

    select * into existing
      from public.lj_auth_email_proofs
     where user_id = p_user_id
     for update;
    if found
       and existing.verified_at is not null
       and existing.invalidated_at is null
       and existing.email_hash = p_email_hash then
        return true;
    end if;

    insert into public.lj_auth_email_proofs (
        user_id, email_hash, proof_source, initiated_at, challenge_expires_at,
        verified_at, evidence_at, proof_session_id, invalidated_at, created_at, updated_at
    ) values (
        p_user_id, p_email_hash, p_source, now(), now() + make_interval(secs => bounded_ttl),
        null, null, null, null, now(), now()
    )
    on conflict (user_id) do update set
        email_hash = excluded.email_hash,
        proof_source = excluded.proof_source,
        initiated_at = excluded.initiated_at,
        challenge_expires_at = excluded.challenge_expires_at,
        verified_at = null,
        evidence_at = null,
        proof_session_id = null,
        invalidated_at = null,
        updated_at = now();
    return true;
end;
$$;

create or replace function public.begin_lj_recovery_challenge(
    p_user_id uuid,
    p_email_hash text
) returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    existing public.lj_auth_recovery_challenges%rowtype;
begin
    if coalesce(auth.role(), '') <> 'service_role' then
        raise exception 'service role required';
    end if;
    if p_email_hash !~ '^[0-9a-f]{64}$'
       or not exists (
           select 1 from public.lj_auth_email_proofs p
            where p.user_id = p_user_id
              and p.email_hash = p_email_hash
              and p.verified_at is not null
              and p.invalidated_at is null
       ) then
        return false;
    end if;
    select * into existing
      from public.lj_auth_recovery_challenges
     where user_id = p_user_id
     for update;
    if found and existing.consumed_at is null and existing.expires_at > now() then
        -- Never replace a generation while password completion owns its lease.
        if existing.claimed_session_id is not null
           and coalesce(existing.claim_expires_at, '-infinity'::timestamptz) > now() then
            return false;
        end if;
        -- A repeat request may send another email for the same still-pending
        -- generation, but cannot change its immutable ID or evidence boundary.
        if existing.email_hash = p_email_hash then
            return true;
        end if;
        -- An email change may replace an unclaimed generation only after the
        -- new address has its own valid LJ email proof (checked above).
    end if;

    insert into public.lj_auth_recovery_challenges (
        user_id, challenge_id, email_hash, requested_at, expires_at, claimed_session_id,
        claim_expires_at, consumed_at, updated_at
    ) values (
        p_user_id, gen_random_uuid(), p_email_hash, now(), now() + interval '1 hour',
        null, null, null, now()
    )
    on conflict (user_id) do update set
        challenge_id = excluded.challenge_id,
        email_hash = excluded.email_hash,
        requested_at = excluded.requested_at,
        expires_at = excluded.expires_at,
        claimed_session_id = null,
        claim_expires_at = null,
        consumed_at = null,
        updated_at = now();
    return true;
end;
$$;

drop function if exists public.claim_lj_recovery_challenge(uuid, text, timestamptz, uuid);
drop function if exists public.finish_lj_recovery_challenge(uuid, uuid);

create or replace function public.claim_lj_recovery_challenge(
    p_user_id uuid,
    p_challenge_id uuid,
    p_email_hash text,
    p_evidence_at timestamptz,
    p_session_id uuid
) returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    challenge public.lj_auth_recovery_challenges%rowtype;
begin
    if coalesce(auth.role(), '') <> 'service_role' then
        raise exception 'service role required';
    end if;
    select * into challenge
      from public.lj_auth_recovery_challenges
     where user_id = p_user_id
     for update;
    if not found
       or challenge.challenge_id <> p_challenge_id
       or challenge.email_hash <> p_email_hash
       or challenge.consumed_at is not null
       or challenge.expires_at <= now()
       or p_evidence_at < challenge.requested_at - interval '60 seconds'
       or p_evidence_at > challenge.expires_at + interval '60 seconds'
       or p_evidence_at > now() + interval '5 minutes'
       or (
           challenge.claimed_session_id is not null
           and coalesce(challenge.claim_expires_at, '-infinity'::timestamptz) > now()
       )
       or exists (
           select 1 from public.lj_auth_recovery_session_uses used
            where used.session_id = p_session_id
       ) then
        return false;
    end if;
    insert into public.lj_auth_recovery_session_uses (
        session_id, user_id, challenge_id, claimed_at
    ) values (
        p_session_id, p_user_id, p_challenge_id, now()
    ) on conflict (session_id) do nothing;
    if not found then
        return false;
    end if;
    update public.lj_auth_recovery_challenges
       set claimed_session_id = p_session_id,
           claim_expires_at = now() + interval '5 minutes',
           updated_at = now()
     where user_id = p_user_id
       and challenge_id = p_challenge_id;
    return true;
end;
$$;

create or replace function public.finish_lj_recovery_challenge(
    p_user_id uuid,
    p_challenge_id uuid,
    p_session_id uuid
) returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
    if coalesce(auth.role(), '') <> 'service_role' then
        raise exception 'service role required';
    end if;
    update public.lj_auth_recovery_challenges
       set consumed_at = now(), updated_at = now()
     where user_id = p_user_id
       and challenge_id = p_challenge_id
       and claimed_session_id = p_session_id
       and claim_expires_at > now()
       and consumed_at is null;
    return found;
end;
$$;

create or replace function public.complete_lj_email_proof(
    p_user_id uuid,
    p_email_hash text,
    p_source text,
    p_evidence_at timestamptz,
    p_session_id uuid default null
) returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    pending public.lj_auth_email_proofs%rowtype;
begin
    if coalesce(auth.role(), '') <> 'service_role' then
        raise exception 'service role required';
    end if;
    select * into pending
      from public.lj_auth_email_proofs
     where user_id = p_user_id
     for update;
    if not found
       or pending.invalidated_at is not null
       or pending.verified_at is not null
       or pending.email_hash <> p_email_hash
       or pending.proof_source <> p_source
       or p_evidence_at is null
       or p_evidence_at < pending.initiated_at - interval '60 seconds'
       or p_evidence_at > pending.challenge_expires_at + interval '60 seconds'
       or p_evidence_at > now() + interval '5 minutes' then
        return false;
    end if;
    if p_source = 'LEGACY_REVERIFICATION'
       and (p_session_id is null or pending.challenge_expires_at <= now()) then
        return false;
    end if;

    update public.lj_auth_email_proofs
       set verified_at = now(),
           evidence_at = p_evidence_at,
           proof_session_id = p_session_id,
           updated_at = now()
     where user_id = p_user_id;
    return true;
end;
$$;

create or replace function public.invalidate_lj_email_proof_on_auth_email_change()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
    if lower(coalesce(old.email, '')) is distinct from lower(coalesce(new.email, '')) then
        update public.lj_auth_email_proofs
           set invalidated_at = now(), updated_at = now()
         where user_id = new.id and invalidated_at is null;
    end if;
    return new;
end;
$$;

drop trigger if exists invalidate_lj_email_proof_on_auth_email_change on auth.users;
create trigger invalidate_lj_email_proof_on_auth_email_change
after update of email on auth.users
for each row execute function public.invalidate_lj_email_proof_on_auth_email_change();

revoke all on function public.begin_lj_email_proof(uuid, text, text, integer) from public, anon, authenticated;
revoke all on function public.complete_lj_email_proof(uuid, text, text, timestamptz, uuid) from public, anon, authenticated;
revoke all on function public.begin_lj_recovery_challenge(uuid, text) from public, anon, authenticated;
revoke all on function public.claim_lj_recovery_challenge(uuid, uuid, text, timestamptz, uuid) from public, anon, authenticated;
revoke all on function public.finish_lj_recovery_challenge(uuid, uuid, uuid) from public, anon, authenticated;
grant execute on function public.begin_lj_email_proof(uuid, text, text, integer) to service_role;
grant execute on function public.complete_lj_email_proof(uuid, text, text, timestamptz, uuid) to service_role;
grant execute on function public.begin_lj_recovery_challenge(uuid, text) to service_role;
grant execute on function public.claim_lj_recovery_challenge(uuid, uuid, text, timestamptz, uuid) to service_role;
grant execute on function public.finish_lj_recovery_challenge(uuid, uuid, uuid) to service_role;

commit;
