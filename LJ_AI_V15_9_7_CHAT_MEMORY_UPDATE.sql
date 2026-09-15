-- LJ AI V15.9.7 conversation, memory and reliable Teach LJ update.
-- Run once in Supabase SQL Editor after LJ_AI_V15_3_DATABASE_UPDATE.sql,
-- LJ_AI_V15_9_MAJOR_UPDATE.sql,
-- LJ_AI_TEACH_LJ_DATABASE_UPDATE.sql, LJ_AI_V15_9_6_SMART_MODE_UPDATE.sql,
-- and LJ_AI_V15_9_6_PAIRED_DEVICE_UPDATE.sql. Safe to run again.
begin;

-- Each password-login attempt is ordered independently from HTTP completion.
-- This prevents an older, slower request from rotating the device token after
-- the GUI has already accepted a newer attempt. Only hashes are persisted.
alter table public.account_devices
    add column if not exists auth_attempt_id text;
alter table public.account_devices
    add column if not exists auth_attempt_started_at timestamptz;
alter table public.account_devices
    add column if not exists auth_attempt_recorded_at timestamptz;

do $$
begin
    if not exists (
        select 1 from pg_constraint
         where conname = 'account_devices_auth_attempt_id_check'
           and conrelid = 'public.account_devices'::regclass
    ) then
        alter table public.account_devices
            add constraint account_devices_auth_attempt_id_check
            check (
                auth_attempt_id is null
                or auth_attempt_id ~ '^[A-Za-z0-9_.:-]{8,128}$'
            ) not valid;
    end if;
end
$$;

drop function if exists public.register_lj_device_attempt(
    uuid,text,text,text,text,text,timestamptz,integer
);
create or replace function public.register_lj_device_attempt(
    p_user_id uuid,
    p_device_id text,
    p_device_name text,
    p_platform text,
    p_token_hash text,
    p_attempt_id text,
    p_attempt_started_at timestamptz,
    p_max_devices integer default 2
)
returns table(
    allowed boolean,
    active_devices integer,
    denial_reason text,
    idempotent boolean
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    r public.account_devices%rowtype;
    v_now timestamptz := clock_timestamp();
    v_active_count integer := 0;
begin
    allowed := false;
    active_devices := 0;
    denial_reason := '';
    idempotent := false;
    if p_user_id is null
       or coalesce(p_device_id, '') !~ '^[A-Za-z0-9_.:-]{8,128}$'
       or coalesce(p_token_hash, '') !~ '^[0-9a-f]{64}$'
       or coalesce(p_attempt_id, '') !~ '^[A-Za-z0-9_.:-]{8,128}$'
       or p_attempt_started_at is null
       or abs(extract(epoch from (v_now - p_attempt_started_at))) > 600
       or p_max_devices is null
       or p_max_devices not between 1 and 10 then
        denial_reason := 'INVALID_REQUEST';
        return next;
        return;
    end if;

    -- Use the original V15.3 lock key so old and new registration functions
    -- cannot race each other while clients roll forward.
    perform pg_advisory_xact_lock(hashtext(p_user_id::text));
    select device.* into r
      from public.account_devices as device
     where device.user_id = p_user_id and device.device_id = p_device_id
     for update;

    if found and r.auth_attempt_id = p_attempt_id then
        if r.device_token_hash <> p_token_hash or not r.is_active then
            denial_reason := 'ATTEMPT_MISMATCH';
            select count(*)::integer into active_devices
              from public.account_devices
             where user_id = p_user_id and is_active = true;
            return next;
            return;
        end if;
        update public.account_devices as device
           set device_name = left(coalesce(nullif(trim(p_device_name), ''), 'LJ AI device'), 80),
               platform = left(coalesce(nullif(trim(p_platform), ''), 'Unknown platform'), 80),
               last_seen_at = v_now
         where device.id = r.id
           and device.user_id = p_user_id
           and device.device_id = p_device_id
           and device.device_token_hash = p_token_hash
           and device.auth_attempt_id = p_attempt_id
           and device.is_active = true;
        allowed := found;
        idempotent := found;
        denial_reason := case when found then '' else 'ATTEMPT_MISMATCH' end;
        select count(*)::integer into active_devices
          from public.account_devices
         where user_id = p_user_id and is_active = true;
        return next;
        return;
    end if;

    -- Only a recent, different attempt participates in ordering. Old device
    -- metadata cannot permanently block login if a client clock is corrected.
    if found
       and r.auth_attempt_id is not null
       and r.auth_attempt_recorded_at >= v_now - interval '15 minutes'
       and r.auth_attempt_started_at >= p_attempt_started_at then
        denial_reason := 'STALE_ATTEMPT';
        select count(*)::integer into active_devices
          from public.account_devices
         where user_id = p_user_id and is_active = true;
        return next;
        return;
    end if;

    if not found or not r.is_active then
        select count(*)::integer into v_active_count
          from public.account_devices
         where user_id = p_user_id and is_active = true;
        if v_active_count >= p_max_devices then
            active_devices := v_active_count;
            denial_reason := 'DEVICE_LIMIT';
            return next;
            return;
        end if;
    end if;

    if r.id is not null then
        update public.account_devices as device
           set device_name = left(coalesce(nullif(trim(p_device_name), ''), 'LJ AI device'), 80),
               platform = left(coalesce(nullif(trim(p_platform), ''), 'Unknown platform'), 80),
               device_token_hash = p_token_hash,
               is_active = true,
               last_seen_at = v_now,
               revoked_at = null,
               auth_attempt_id = p_attempt_id,
               auth_attempt_started_at = p_attempt_started_at,
               auth_attempt_recorded_at = v_now
         where device.id = r.id
           and device.user_id = p_user_id
           and device.device_id = p_device_id
           and device.device_token_hash = r.device_token_hash
           and device.is_active = r.is_active
           and device.auth_attempt_id is not distinct from r.auth_attempt_id;
        if not found then
            denial_reason := 'STALE_ATTEMPT';
            return next;
            return;
        end if;
    else
        insert into public.account_devices(
            user_id, device_id, device_name, platform, device_token_hash,
            is_active, created_at, last_seen_at, revoked_at,
            auth_attempt_id, auth_attempt_started_at, auth_attempt_recorded_at
        ) values (
            p_user_id, p_device_id,
            left(coalesce(nullif(trim(p_device_name), ''), 'LJ AI device'), 80),
            left(coalesce(nullif(trim(p_platform), ''), 'Unknown platform'), 80),
            p_token_hash, true, v_now, v_now, null,
            p_attempt_id, p_attempt_started_at, v_now
        );
    end if;

    select count(*)::integer into active_devices
      from public.account_devices
     where user_id = p_user_id and is_active = true;
    allowed := true;
    return next;
end
$$;

-- A detached logout may arrive after a fresh login. It is therefore a no-op
-- unless the exact credential that authenticated the request is still current.
drop function if exists public.revoke_lj_device_session(uuid,text,text);
create or replace function public.revoke_lj_device_session(
    p_user_id uuid,
    p_device_id text,
    p_token_hash text
)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
    if p_user_id is null
       or coalesce(p_device_id, '') !~ '^[A-Za-z0-9_.:-]{8,128}$'
       or coalesce(p_token_hash, '') !~ '^[0-9a-f]{64}$' then
        return false;
    end if;
    perform pg_advisory_xact_lock(hashtext(p_user_id::text));
    update public.account_devices as device
       set is_active = false,
           revoked_at = clock_timestamp(),
           last_seen_at = clock_timestamp()
     where device.user_id = p_user_id
       and device.device_id = p_device_id
       and device.device_token_hash = p_token_hash
       and device.is_active = true;
    return found;
end
$$;

-- Conversation metadata used by the Windows and Android thread lists.
alter table public.lj_conversations
    add column if not exists pinned boolean not null default false;
alter table public.lj_conversations
    add column if not exists archived_at timestamptz;
alter table public.lj_conversations
    add column if not exists last_message_preview text;
alter table public.lj_conversations
    add column if not exists message_count integer not null default 0;

create unique index if not exists lj_conversations_id_owner_uidx
    on public.lj_conversations(id, user_id);
create index if not exists lj_conversations_owner_page_idx
    on public.lj_conversations(user_id, archived_at, pinned desc, updated_at desc, id desc);

-- Existing V15.9.6 chats should look complete in the new thread list on the
-- first launch, not show zero messages until another reply is generated.
with existing_chat_summary as (
    select
        conversation_id,
        user_id,
        count(*)::integer as total_messages,
        (array_agg(left(content, 240) order by created_at desc, id desc))[1] as latest_preview
    from public.lj_conversation_messages
    group by conversation_id, user_id
)
update public.lj_conversations as conversation
   set message_count = summary.total_messages,
       last_message_preview = summary.latest_preview
  from existing_chat_summary as summary
 where conversation.id = summary.conversation_id
   and conversation.user_id = summary.user_id
   and (
       conversation.message_count is distinct from summary.total_messages
       or conversation.last_message_preview is distinct from summary.latest_preview
   );

create or replace function public.enforce_lj_conversation_cap()
returns trigger
language plpgsql
set search_path = public, pg_temp
as $$
begin
    if tg_op = 'INSERT' then
        perform pg_advisory_xact_lock(hashtextextended(new.user_id::text, 1597));
        if (select count(*) from public.lj_conversations where user_id = new.user_id) >= 500 then
            raise exception 'saved conversation limit reached';
        end if;
        if new.archived_at is null and (
            select count(*) from public.lj_conversations
             where user_id = new.user_id and archived_at is null
        ) >= 100 then
            raise exception 'active conversation limit reached';
        end if;
    elsif new.archived_at is null and old.archived_at is not null then
        perform pg_advisory_xact_lock(hashtextextended(new.user_id::text, 1597));
        if (
            select count(*) from public.lj_conversations
             where user_id = new.user_id and archived_at is null
        ) >= 100 then
            raise exception 'active conversation limit reached';
        end if;
    end if;
    return new;
end
$$;

drop trigger if exists lj_conversations_cap_insert_update on public.lj_conversations;
create trigger lj_conversations_cap_insert_update
before insert or update of archived_at on public.lj_conversations
for each row execute function public.enforce_lj_conversation_cap();

alter table public.lj_conversation_messages
    add column if not exists request_id text;
alter table public.lj_conversation_messages
    add column if not exists model text;
alter table public.lj_conversation_messages
    add column if not exists metadata jsonb not null default '{}'::jsonb;

create unique index if not exists lj_messages_request_role_uidx
    on public.lj_conversation_messages(conversation_id, user_id, request_id, role)
    where request_id is not null;
create index if not exists lj_messages_conversation_page_idx
    on public.lj_conversation_messages(conversation_id, user_id, created_at desc, id desc);

create or replace function public.enforce_lj_conversation_message_cap()
returns trigger
language plpgsql
set search_path = public, pg_temp
as $$
begin
    perform 1 from public.lj_conversations
     where id = new.conversation_id and user_id = new.user_id
     for update;
    if (
        select count(*) from public.lj_conversation_messages
         where conversation_id = new.conversation_id and user_id = new.user_id
    ) >= 2000 then
        raise exception 'conversation message limit reached';
    end if;
    return new;
end
$$;

drop trigger if exists lj_messages_cap_insert on public.lj_conversation_messages;
create trigger lj_messages_cap_insert
before insert on public.lj_conversation_messages
for each row execute function public.enforce_lj_conversation_message_cap();

do $$
begin
    if not exists (
        select 1 from pg_constraint
        where conname = 'lj_messages_conversation_owner_fk'
          and conrelid = 'public.lj_conversation_messages'::regclass
    ) then
        alter table public.lj_conversation_messages
            add constraint lj_messages_conversation_owner_fk
            foreign key (conversation_id, user_id)
            references public.lj_conversations(id, user_id)
            on delete cascade not valid;
    end if;
end
$$;

-- Voice metering uses its own monotonic checkpoint. updated_at also changes
-- for handover/state metadata and therefore cannot safely be a billing clock.
alter table public.lj_voice_sessions
    add column if not exists metered_at timestamptz;
alter table public.lj_voice_sessions
    add column if not exists prepaid_seconds integer not null default 0;
alter table public.lj_voice_sessions
    add column if not exists issuance_pending boolean not null default false;
update public.lj_voice_sessions
   set metered_at = coalesce(updated_at, created_at, now())
 where metered_at is null;
alter table public.lj_voice_sessions
    alter column metered_at set default now();
alter table public.lj_voice_sessions
    alter column metered_at set not null;
alter table public.lj_voice_sessions
    drop constraint if exists lj_voice_sessions_prepaid_seconds_check;
alter table public.lj_voice_sessions
    add constraint lj_voice_sessions_prepaid_seconds_check
    check (prepaid_seconds between 0 and 86400);

-- Older builds could race two starts. Keep the newest live lease and prevent
-- that race at the database boundary from V15.9.7 onward.
with ranked_live_voice as (
    select id, row_number() over (
        partition by user_id order by updated_at desc, created_at desc, id desc
    ) as live_rank
    from public.lj_voice_sessions
    where status in ('ACTIVE', 'HANDOVER_REQUESTED')
)
update public.lj_voice_sessions as voice
   set status = 'ENDED',
       lease_expires_at = least(voice.lease_expires_at, now()),
       updated_at = now()
  from ranked_live_voice as ranked
 where voice.id = ranked.id and ranked.live_rank > 1;

create unique index if not exists lj_voice_sessions_one_live_owner_uidx
    on public.lj_voice_sessions(user_id)
    where status in ('ACTIVE', 'HANDOVER_REQUESTED');

do $$
begin
    if not exists (
        select 1 from pg_constraint
        where conname = 'lj_voice_conversation_owner_fk'
          and conrelid = 'public.lj_voice_sessions'::regclass
    ) then
        alter table public.lj_voice_sessions
            add constraint lj_voice_conversation_owner_fk
            foreign key (conversation_id, user_id)
            references public.lj_conversations(id, user_id)
            on delete cascade not valid;
    end if;
end
$$;

-- User-controlled durable memory. Only the service role can access rows;
-- the API applies the additional sensitive-data and ownership policy.
create table if not exists public.lj_memories (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users(id) on delete cascade,
    fact text not null check (char_length(fact) between 1 and 500),
    normalized_fact text not null check (char_length(normalized_fact) between 1 and 500),
    category text not null default 'OTHER'
        check (category in ('PREFERENCE', 'PROFILE', 'PROJECT', 'OTHER')),
    enabled boolean not null default true,
    source_conversation_id text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (id, user_id),
    unique (user_id, normalized_fact)
);

-- Keep user-approved memories independent from their source chat. PostgreSQL
-- 15's column-list SET NULL clears only the nullable conversation reference;
-- the non-null owner column remains intact and owner-bound.
alter table public.lj_memories
    drop constraint if exists lj_memories_source_conversation_id_user_id_fkey;
alter table public.lj_memories
    drop constraint if exists lj_memories_source_conversation_owner_fk;
alter table public.lj_memories
    add constraint lj_memories_source_conversation_owner_fk
    foreign key (source_conversation_id, user_id)
    references public.lj_conversations(id, user_id)
    on delete set null (source_conversation_id) not valid;

create or replace function public.enforce_lj_memory_cap()
returns trigger
language plpgsql
set search_path = public, pg_temp
as $$
begin
    perform pg_advisory_xact_lock(hashtextextended(new.user_id::text, 159700));
    if (select count(*) from public.lj_memories where user_id = new.user_id) >= 200 then
        raise exception 'saved memory limit reached';
    end if;
    return new;
end
$$;

drop trigger if exists lj_memories_cap_insert on public.lj_memories;
create trigger lj_memories_cap_insert
before insert on public.lj_memories
for each row execute function public.enforce_lj_memory_cap();

create index if not exists lj_memories_owner_page_idx
    on public.lj_memories(user_id, enabled desc, updated_at desc, id desc);

alter table public.lj_memories enable row level security;
revoke all on table public.lj_memories from public, anon, authenticated;
grant select, insert, update, delete on table public.lj_memories to service_role;

create or replace function public.set_lj_memory_enabled(
    p_user_id uuid,
    p_enabled boolean
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    saved public.lj_user_preferences%rowtype;
begin
    insert into public.lj_user_preferences as prefs(user_id, values, revision, updated_at)
    values(p_user_id, jsonb_build_object('memory_enabled', p_enabled), 1, now())
    on conflict (user_id) do update
        set values = coalesce(prefs.values, '{}'::jsonb)
                     || jsonb_build_object('memory_enabled', p_enabled),
            revision = prefs.revision + 1,
            updated_at = now()
    returning * into saved;
    return jsonb_build_object(
        'enabled', coalesce((saved.values->>'memory_enabled')::boolean, true),
        'revision', saved.revision,
        'updated_at', saved.updated_at
    );
end
$$;

-- Exact spoken aliases for Teach LJ. There is deliberately no fuzzy match:
-- a spoken command runs only when its normalized name/alias has one owner.
create table if not exists public.lj_skill_triggers (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users(id) on delete cascade,
    skill_id uuid not null,
    phrase text not null check (char_length(phrase) between 1 and 100),
    normalized_phrase text not null check (char_length(normalized_phrase) between 1 and 100),
    created_at timestamptz not null default now(),
    unique (user_id, normalized_phrase),
    foreign key (skill_id, user_id)
        references public.lj_skills(id, user_id) on delete cascade
);

create index if not exists lj_skill_triggers_skill_idx
    on public.lj_skill_triggers(user_id, skill_id, created_at);

alter table public.lj_skill_triggers enable row level security;
revoke all on table public.lj_skill_triggers from public, anon, authenticated;
grant select, insert, update, delete on table public.lj_skill_triggers to service_role;

-- Both runs and versions are owned children of the account. RESTRICT on this
-- composite edge can otherwise block the auth user's cascading hard deletion.
alter table public.lj_skill_runs
    drop constraint if exists lj_skill_runs_skill_id_skill_version_user_id_fkey;
alter table public.lj_skill_runs
    drop constraint if exists lj_skill_runs_version_owner_fk;
alter table public.lj_skill_runs
    add constraint lj_skill_runs_version_owner_fk
    foreign key (skill_id, skill_version, user_id)
    references public.lj_skill_versions(skill_id, version, user_id)
    on delete cascade not valid;

-- Runtime variables can contain message bodies, file paths or other temporary
-- user values. They are needed only while a run is active.
create or replace function public.scrub_terminal_lj_skill_run()
returns trigger
language plpgsql
set search_path = public, pg_temp
as $$
begin
    if new.status in ('SUCCEEDED', 'FAILED', 'CANCELLED') then
        new.variables := '{}'::jsonb;
        new.pending_confirmation := null;
        new.confirmation_token_hash := null;
        new.confirmation_expires_at := null;
    end if;
    return new;
end
$$;

drop trigger if exists lj_skill_runs_scrub_terminal on public.lj_skill_runs;
create trigger lj_skill_runs_scrub_terminal
before insert or update of status on public.lj_skill_runs
for each row execute function public.scrub_terminal_lj_skill_run();

update public.lj_skill_runs
   set variables = '{}'::jsonb,
       pending_confirmation = null,
       confirmation_token_hash = null,
       confirmation_expires_at = null
 where status in ('SUCCEEDED', 'FAILED', 'CANCELLED')
   and (
       variables <> '{}'::jsonb
       or pending_confirmation is not null
       or confirmation_token_hash is not null
       or confirmation_expires_at is not null
   );

create or replace function public.replace_lj_skill_triggers(
    p_user_id uuid,
    p_skill_id uuid,
    p_aliases jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    item jsonb;
    phrase_value text;
    normalized_value text;
    result jsonb;
begin
    if not exists (
        select 1 from public.lj_skills
         where id = p_skill_id and user_id = p_user_id and deleted_at is null
    ) then
        raise exception 'skill unavailable';
    end if;
    if jsonb_typeof(coalesce(p_aliases, '[]'::jsonb)) <> 'array'
       or jsonb_array_length(coalesce(p_aliases, '[]'::jsonb)) > 20 then
        raise exception 'invalid skill aliases';
    end if;

    delete from public.lj_skill_triggers
     where user_id = p_user_id and skill_id = p_skill_id;
    for item in select value from jsonb_array_elements(coalesce(p_aliases, '[]'::jsonb)) loop
        phrase_value := trim(coalesce(item->>'phrase', ''));
        normalized_value := trim(coalesce(item->>'normalized_phrase', ''));
        if char_length(phrase_value) not between 1 and 100
           or char_length(normalized_value) not between 1 and 100
           or normalized_value !~ '^[a-z0-9]+( [a-z0-9]+)*$' then
            raise exception 'invalid skill alias';
        end if;
        insert into public.lj_skill_triggers(user_id, skill_id, phrase, normalized_phrase)
        values(p_user_id, p_skill_id, phrase_value, normalized_value);
    end loop;

    select coalesce(jsonb_agg(jsonb_build_object(
        'id', id,
        'phrase', phrase,
        'normalized_phrase', normalized_phrase,
        'created_at', created_at
    ) order by created_at, id), '[]'::jsonb)
      into result
      from public.lj_skill_triggers
     where user_id = p_user_id and skill_id = p_skill_id;
    return result;
end
$$;

-- Per-request reservations let the API undo only the failed request's charge.
create table if not exists public.lj_chat_usage_reservations (
    user_id uuid not null references auth.users(id) on delete cascade,
    request_id text not null check (char_length(request_id) between 8 and 100),
    request_fingerprint text not null check (request_fingerprint ~ '^[0-9a-f]{64}$'),
    mode text not null check (mode in ('NORMAL', 'SMART', 'DEEP_THINK', 'DEVELOPER')),
    cycle_start timestamptz not null,
    claim_token text not null check (claim_token ~ '^[0-9a-f]{64}$'),
    status text not null constraint lj_chat_usage_reservations_status_check
        check (status in ('IN_PROGRESS', 'COMPLETED', 'REFUNDED')),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    primary key (user_id, request_id)
);

alter table public.lj_chat_usage_reservations
    add column if not exists request_fingerprint text;
alter table public.lj_chat_usage_reservations
    add column if not exists claim_token text;
update public.lj_chat_usage_reservations
   set request_fingerprint = repeat('0', 64)
 where request_fingerprint is null;
update public.lj_chat_usage_reservations
   set claim_token = replace(gen_random_uuid()::text, '-', '')
                     || replace(gen_random_uuid()::text, '-', '')
 where claim_token is null;
alter table public.lj_chat_usage_reservations
    alter column request_fingerprint set not null;
alter table public.lj_chat_usage_reservations
    alter column claim_token set not null;
alter table public.lj_chat_usage_reservations
    drop constraint if exists lj_chat_usage_reservations_status_check;
update public.lj_chat_usage_reservations
   set status = 'IN_PROGRESS'
 where status = 'CHARGED';
alter table public.lj_chat_usage_reservations
    add constraint lj_chat_usage_reservations_status_check
    check (status in ('IN_PROGRESS', 'COMPLETED', 'REFUNDED'));
alter table public.lj_chat_usage_reservations
    drop constraint if exists lj_chat_usage_reservations_request_fingerprint_check;
alter table public.lj_chat_usage_reservations
    add constraint lj_chat_usage_reservations_request_fingerprint_check
    check (request_fingerprint ~ '^[0-9a-f]{64}$');
alter table public.lj_chat_usage_reservations
    drop constraint if exists lj_chat_usage_reservations_claim_token_check;
alter table public.lj_chat_usage_reservations
    add constraint lj_chat_usage_reservations_claim_token_check
    check (claim_token ~ '^[0-9a-f]{64}$');

alter table public.lj_chat_usage_reservations enable row level security;
revoke all on table public.lj_chat_usage_reservations from public, anon, authenticated;
grant select, insert, update, delete on table public.lj_chat_usage_reservations to service_role;

drop function if exists public.reserve_lj_chat_usage(uuid,text,text,text);
create or replace function public.reserve_lj_chat_usage(
    p_user_id uuid,
    p_request_id text,
    p_request_fingerprint text,
    p_mode text default 'NORMAL'
)
returns table(
    allowed boolean,
    denial_reason text,
    plan_key text,
    text_remaining integer,
    max_reasoning_remaining integer,
    reservation_status text,
    claim_token text
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    c public.lj_usage_cycles%rowtype;
    r public.lj_chat_usage_reservations%rowtype;
    m text := upper(coalesce(p_mode, 'NORMAL'));
    use_max boolean;
    reservation_exists boolean := false;
    v_claim_token text;
begin
    if p_user_id is null
       or char_length(trim(coalesce(p_request_id, ''))) not between 8 and 100
       or coalesce(p_request_fingerprint, '') !~ '^[0-9a-f]{64}$'
       or m not in ('NORMAL', 'SMART', 'DEEP_THINK', 'DEVELOPER') then
        raise exception 'invalid chat reservation';
    end if;

    -- The row may not exist yet, so SELECT ... FOR UPDATE alone cannot stop
    -- two simultaneous uses of a brand-new request_id. This transaction lock
    -- serializes that exact owner/request pair before either caller can claim
    -- it. Hash collisions only serialize unrelated requests; they never make
    -- one user's reservation visible to another user.
    perform pg_advisory_xact_lock(
        hashtextextended(p_user_id::text || ':' || trim(p_request_id), 1597)
    );

    select * into r
      from public.lj_chat_usage_reservations
     where user_id = p_user_id and request_id = trim(p_request_id)
     for update;
    reservation_exists := found;

    c := public.ensure_lj_usage_cycle(p_user_id);
    use_max := m = 'DEVELOPER';

    if reservation_exists and r.request_fingerprint <> p_request_fingerprint then
        allowed := false;
        denial_reason := 'REQUEST_ID_REUSED';
        plan_key := c.plan_key;
        text_remaining := case when c.text_limit is null then null else greatest(0, c.text_limit - c.text_used) end;
        max_reasoning_remaining := case when c.max_reasoning_limit is null then null else greatest(0, c.max_reasoning_limit - c.max_reasoning_used) end;
        reservation_status := r.status;
        claim_token := null;
        return next;
        return;
    end if;

    if reservation_exists and r.status = 'COMPLETED' then
        allowed := false;
        denial_reason := 'ALREADY_COMPLETED';
        plan_key := c.plan_key;
        text_remaining := case when c.text_limit is null then null else greatest(0, c.text_limit - c.text_used) end;
        max_reasoning_remaining := case when c.max_reasoning_limit is null then null else greatest(0, c.max_reasoning_limit - c.max_reasoning_used) end;
        reservation_status := r.status;
        claim_token := null;
        return next;
        return;
    end if;

    if reservation_exists and r.status = 'IN_PROGRESS'
       and r.updated_at > now() - interval '10 minutes' then
        allowed := false;
        denial_reason := 'REQUEST_IN_PROGRESS';
        plan_key := c.plan_key;
        text_remaining := case when c.text_limit is null then null else greatest(0, c.text_limit - c.text_used) end;
        max_reasoning_remaining := case when c.max_reasoning_limit is null then null else greatest(0, c.max_reasoning_limit - c.max_reasoning_used) end;
        reservation_status := 'IN_PROGRESS';
        claim_token := null;
        return next;
        return;
    end if;

    if reservation_exists and r.status = 'IN_PROGRESS' then
        v_claim_token := replace(gen_random_uuid()::text, '-', '')
                         || replace(gen_random_uuid()::text, '-', '');
        update public.lj_chat_usage_reservations
           set claim_token = v_claim_token,
               updated_at = now()
         where user_id = p_user_id and request_id = trim(p_request_id);
        allowed := true;
        denial_reason := '';
        plan_key := c.plan_key;
        text_remaining := case when c.text_limit is null then null else greatest(0, c.text_limit - c.text_used) end;
        max_reasoning_remaining := case when c.max_reasoning_limit is null then null else greatest(0, c.max_reasoning_limit - c.max_reasoning_used) end;
        reservation_status := 'RECLAIMED';
        claim_token := v_claim_token;
        return next;
        return;
    end if;

    -- Administrator usage is unlimited, but it still needs a reservation.
    -- The reservation is the concurrency/idempotency guard, not only quota
    -- accounting. Deliberately do not increment either usage counter here.
    if c.plan_key = 'ADMIN' then
        v_claim_token := replace(gen_random_uuid()::text, '-', '')
                         || replace(gen_random_uuid()::text, '-', '');
        insert into public.lj_chat_usage_reservations(
            user_id, request_id, request_fingerprint, mode, cycle_start, claim_token, status
        ) values (
            p_user_id, trim(p_request_id), p_request_fingerprint, m, c.cycle_start,
            v_claim_token, 'IN_PROGRESS'
        )
        on conflict (user_id, request_id) do update
            set request_fingerprint = excluded.request_fingerprint,
                mode = excluded.mode,
                cycle_start = excluded.cycle_start,
                claim_token = excluded.claim_token,
                status = 'IN_PROGRESS',
                updated_at = now();
        allowed := true;
        denial_reason := '';
        plan_key := c.plan_key;
        text_remaining := null;
        max_reasoning_remaining := null;
        reservation_status := 'CLAIMED';
        claim_token := v_claim_token;
        return next;
        return;
    end if;

    if c.text_limit is not null and c.text_used + 1 > c.text_limit then
        allowed := false;
        denial_reason := 'TEXT_LIMIT';
    elsif use_max and c.plan_key not in ('VIP', 'ADMIN') then
        allowed := false;
        denial_reason := 'MODE_NOT_INCLUDED';
    elsif use_max and c.max_reasoning_limit is not null
          and c.max_reasoning_used + 1 > c.max_reasoning_limit then
        allowed := false;
        denial_reason := 'MAX_REASONING_LIMIT';
    else
        v_claim_token := replace(gen_random_uuid()::text, '-', '')
                         || replace(gen_random_uuid()::text, '-', '');
        update public.lj_usage_cycles
           set text_used = text_used + 1,
               max_reasoning_used = max_reasoning_used + case when use_max then 1 else 0 end,
               updated_at = now()
         where user_id = p_user_id and cycle_start = c.cycle_start
         returning * into c;

        insert into public.lj_chat_usage_reservations(
            user_id, request_id, request_fingerprint, mode, cycle_start, claim_token, status
        ) values (
            p_user_id, trim(p_request_id), p_request_fingerprint, m, c.cycle_start,
            v_claim_token, 'IN_PROGRESS'
        )
        on conflict (user_id, request_id) do update
            set request_fingerprint = excluded.request_fingerprint,
                mode = excluded.mode,
                cycle_start = excluded.cycle_start,
                claim_token = excluded.claim_token,
                status = 'IN_PROGRESS',
                updated_at = now();
        allowed := true;
        denial_reason := '';
    end if;

    plan_key := c.plan_key;
    text_remaining := case when c.text_limit is null then null else greatest(0, c.text_limit - c.text_used) end;
    max_reasoning_remaining := case when c.max_reasoning_limit is null then null else greatest(0, c.max_reasoning_limit - c.max_reasoning_used) end;
    reservation_status := case when allowed then 'CLAIMED' else 'DENIED' end;
    claim_token := case when allowed then v_claim_token else null end;
    return next;
end
$$;

drop function if exists public.complete_lj_chat_usage(uuid,text);
create or replace function public.complete_lj_chat_usage(
    p_user_id uuid,
    p_request_id text,
    p_claim_token text
)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    changed integer;
begin
    update public.lj_chat_usage_reservations
       set status = 'COMPLETED', updated_at = now()
     where user_id = p_user_id
       and request_id = trim(coalesce(p_request_id, ''))
       and claim_token = coalesce(p_claim_token, '')
       and status = 'IN_PROGRESS';
    get diagnostics changed = row_count;
    return changed = 1;
end
$$;

drop function if exists public.refund_lj_chat_usage(uuid,text);
create or replace function public.refund_lj_chat_usage(
    p_user_id uuid,
    p_request_id text,
    p_claim_token text
)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    r public.lj_chat_usage_reservations%rowtype;
begin
    select * into r
      from public.lj_chat_usage_reservations
     where user_id = p_user_id and request_id = trim(coalesce(p_request_id, ''))
     for update;
    if not found
       or r.status <> 'IN_PROGRESS'
       or r.claim_token <> coalesce(p_claim_token, '') then
        return false;
    end if;

    update public.lj_usage_cycles
       set text_used = greatest(0, text_used - 1),
           max_reasoning_used = greatest(
               0,
               max_reasoning_used - case when r.mode = 'DEVELOPER' then 1 else 0 end
           ),
           updated_at = now()
     where user_id = p_user_id
       and cycle_start = r.cycle_start
       and plan_key <> 'ADMIN';

    update public.lj_chat_usage_reservations
       set status = 'REFUNDED', updated_at = now()
     where user_id = p_user_id and request_id = r.request_id;
    return true;
end
$$;

-- One transaction saves both visible sides of a generated turn and completes
-- the exact active claim. A stale worker cannot save after another caller has
-- reclaimed the request_id with a new claim token.
drop function if exists public.save_lj_chat_turn(uuid,text,text,text,text,text,text);
create or replace function public.save_lj_chat_turn(
    p_user_id uuid,
    p_conversation_id text,
    p_request_id text,
    p_claim_token text,
    p_user_content text,
    p_assistant_content text,
    p_model text,
    p_source_device_id text default null
)
returns table(user_message_id text, assistant_message_id text, saved_at timestamptz)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_user_message_id text;
    v_assistant_message_id text;
    v_saved_at timestamptz := now();
    v_message_count integer := 0;
    v_request_rows integer := 0;
begin
    perform 1 from public.lj_chat_usage_reservations
     where user_id = p_user_id
       and request_id = trim(coalesce(p_request_id, ''))
       and claim_token = coalesce(p_claim_token, '')
       and status = 'IN_PROGRESS'
     for update;
    if not found then
        raise exception 'chat reservation unavailable';
    end if;

    perform 1 from public.lj_conversations
     where id = p_conversation_id and user_id = p_user_id
     for update;
    if not found then
        raise exception 'conversation unavailable';
    end if;
    if char_length(trim(coalesce(p_request_id, ''))) not between 8 and 100
       or char_length(trim(coalesce(p_user_content, ''))) not between 1 and 8000
       or char_length(trim(coalesce(p_assistant_content, ''))) not between 1 and 20000 then
        raise exception 'invalid chat turn';
    end if;

    select count(*)::integer,
           count(*) filter (where request_id = trim(p_request_id))::integer
      into v_message_count, v_request_rows
      from public.lj_conversation_messages
     where conversation_id = p_conversation_id and user_id = p_user_id;
    if v_request_rows = 0 and v_message_count > 1998 then
        raise exception 'conversation message limit reached';
    end if;

    select id into v_user_message_id
      from public.lj_conversation_messages
     where conversation_id = p_conversation_id
       and user_id = p_user_id
       and request_id = trim(p_request_id)
       and role = 'user'
     limit 1;
    if v_user_message_id is null then
        v_user_message_id := gen_random_uuid()::text;
        insert into public.lj_conversation_messages(
            id, conversation_id, user_id, role, content, images,
            source_device_id, request_id, model, metadata, created_at
        ) values (
            v_user_message_id, p_conversation_id, p_user_id, 'user', trim(p_user_content), '[]'::jsonb,
            nullif(trim(coalesce(p_source_device_id, '')), ''), trim(p_request_id), null, '{}'::jsonb, v_saved_at
        ) on conflict do nothing;
        select id into v_user_message_id
          from public.lj_conversation_messages
         where conversation_id = p_conversation_id and user_id = p_user_id
           and request_id = trim(p_request_id) and role = 'user'
         limit 1;
    end if;

    select id into v_assistant_message_id
      from public.lj_conversation_messages
     where conversation_id = p_conversation_id
       and user_id = p_user_id
       and request_id = trim(p_request_id)
       and role = 'assistant'
     limit 1;
    if v_assistant_message_id is null then
        v_assistant_message_id := gen_random_uuid()::text;
        insert into public.lj_conversation_messages(
            id, conversation_id, user_id, role, content, images,
            source_device_id, request_id, model, metadata, created_at
        ) values (
            v_assistant_message_id, p_conversation_id, p_user_id, 'assistant', trim(p_assistant_content), '[]'::jsonb,
            null, trim(p_request_id), nullif(trim(coalesce(p_model, '')), ''), '{}'::jsonb,
            v_saved_at + interval '1 microsecond'
        ) on conflict do nothing;
        select id into v_assistant_message_id
          from public.lj_conversation_messages
         where conversation_id = p_conversation_id and user_id = p_user_id
           and request_id = trim(p_request_id) and role = 'assistant'
         limit 1;
    end if;

    if v_user_message_id is null or v_assistant_message_id is null then
        raise exception 'chat turn could not be saved';
    end if;

    update public.lj_conversations
       set updated_at = v_saved_at,
           title = case
               when lower(trim(title)) in ('new conversation', 'new chat')
                   then left(trim(p_user_content), 80)
               else title
           end,
           last_message_preview = left(trim(p_assistant_content), 240),
           message_count = (
               select count(*)::integer from public.lj_conversation_messages
                where conversation_id = p_conversation_id and user_id = p_user_id
           )
     where id = p_conversation_id and user_id = p_user_id;

    update public.lj_chat_usage_reservations
       set status = 'COMPLETED', updated_at = now()
     where user_id = p_user_id
       and request_id = trim(p_request_id)
       and claim_token = coalesce(p_claim_token, '')
       and status = 'IN_PROGRESS';

    user_message_id := v_user_message_id;
    assistant_message_id := v_assistant_message_id;
    saved_at := v_saved_at;
    return next;
end
$$;

create or replace function public.delete_lj_conversation(
    p_user_id uuid,
    p_conversation_id text
)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    removed integer;
begin
    delete from public.lj_conversations
     where id = p_conversation_id and user_id = p_user_id;
    get diagnostics removed = row_count;
    return removed = 1;
end
$$;

-- Atomically validate one voice lease, account for elapsed time exactly once,
-- and advance/end/transfer the lease in the same transaction. The service
-- passes SHA-256 lease hashes; raw lease tokens never enter the database.
drop function if exists public.apply_lj_voice_session(
    uuid,text,text,text,text,jsonb,text,text,text,text,text
);
create or replace function public.apply_lj_voice_session(
    p_user_id uuid,
    p_session_id text,
    p_device_id text,
    p_lease_token_hash text,
    p_action text,
    p_transcript_tail jsonb default null,
    p_voice_state text default null,
    p_target_platform text default null,
    p_new_device_id text default null,
    p_new_platform text default null,
    p_new_lease_token_hash text default null
)
returns table(
    applied boolean,
    denial_reason text,
    session_state text,
    seconds_charged integer,
    voice_seconds_remaining integer,
    allowance_exhausted boolean,
    lease_expires_at timestamptz,
    prepaid_seconds integer,
    already_ended boolean
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    r public.lj_voice_sessions%rowtype;
    c public.lj_usage_cycles%rowtype;
    v_action text := upper(trim(coalesce(p_action, '')));
    v_now timestamptz := clock_timestamp();
    v_elapsed integer := 0;
    v_prepaid_used integer := 0;
    v_prepaid_left integer := 0;
    v_billable integer := 0;
    v_db_remaining integer;
    v_new_charge integer := 0;
    v_effective_remaining integer;
    v_new_status text;
    v_expiry timestamptz;
    v_expired boolean := false;
begin
    applied := false;
    denial_reason := '';
    seconds_charged := 0;
    allowance_exhausted := false;
    already_ended := false;

    if v_action not in ('HEARTBEAT', 'END', 'OFFER', 'CLAIM', 'ABORT')
       or char_length(trim(coalesce(p_session_id, ''))) not between 8 and 100
       or char_length(trim(coalesce(p_device_id, ''))) not between 8 and 128
       or coalesce(p_lease_token_hash, '') !~ '^[0-9a-f]{64}$'
       or (p_transcript_tail is not null and jsonb_typeof(p_transcript_tail) <> 'array')
       or (p_voice_state is not null and upper(p_voice_state) not in ('LISTENING', 'SPEAKING', 'IDLE')) then
        denial_reason := 'INVALID_REQUEST';
        return next;
        return;
    end if;

    -- Every voice debit for one account shares this transaction lock.  The
    -- lease row lock prevents duplicate heartbeats for one session; the
    -- advisory lock also serialises standalone STT/TTS debits and a heartbeat
    -- on a different device at the usage-ledger boundary.
    perform pg_advisory_xact_lock(hashtextextended(p_user_id::text, 159701));

    select voice.* into r
      from public.lj_voice_sessions as voice
     where voice.id = trim(p_session_id) and voice.user_id = p_user_id
     for update;
    if not found then
        denial_reason := 'SESSION_NOT_FOUND';
        return next;
        return;
    end if;
    if r.active_device_id <> trim(p_device_id)
       or r.lease_token_hash <> p_lease_token_hash then
        denial_reason := 'LEASE_MISMATCH';
        session_state := r.status;
        lease_expires_at := r.lease_expires_at;
        return next;
        return;
    end if;

    -- ABORT is exclusively for the service-created lease that exists while
    -- OpenAI client-secret issuance is still pending. It deliberately does
    -- not meter setup latency. Exact owner/session/device/token matching above,
    -- plus the pending + zero-prepayment checks below, prevent it from being
    -- used to erase time from a real or already-reserved voice session.
    if v_action = 'ABORT' then
        if not r.issuance_pending or r.prepaid_seconds <> 0 or r.status = 'ENDED' then
            denial_reason := 'ABORT_UNAVAILABLE';
            session_state := r.status;
            lease_expires_at := r.lease_expires_at;
            return next;
            return;
        end if;
        update public.lj_voice_sessions as voice
           set status = 'ENDED',
               issuance_pending = false,
               handover_target = null,
               metered_at = v_now,
               lease_expires_at = v_now,
               updated_at = v_now
         where voice.id = r.id
           and voice.user_id = p_user_id
           and voice.active_device_id = trim(p_device_id)
           and voice.lease_token_hash = p_lease_token_hash
           and voice.issuance_pending
           and voice.prepaid_seconds = 0;
        if not found then
            denial_reason := 'ABORT_UNAVAILABLE';
            return next;
            return;
        end if;
        c := public.ensure_lj_usage_cycle(p_user_id);
        applied := true;
        session_state := 'ENDED';
        seconds_charged := 0;
        voice_seconds_remaining := case
            when c.voice_seconds_limit is null then null
            else greatest(0, c.voice_seconds_limit - c.voice_seconds_used)
        end;
        allowance_exhausted := c.voice_seconds_limit is not null
            and voice_seconds_remaining <= 0;
        lease_expires_at := v_now;
        prepaid_seconds := 0;
        already_ended := false;
        return next;
        return;
    end if;

    if r.issuance_pending then
        denial_reason := 'ISSUANCE_PENDING';
        session_state := r.status;
        lease_expires_at := r.lease_expires_at;
        return next;
        return;
    end if;

    c := public.ensure_lj_usage_cycle(p_user_id);
    if r.status = 'ENDED' then
        session_state := 'ENDED';
        seconds_charged := 0;
        voice_seconds_remaining := case
            when c.voice_seconds_limit is null then null
            else greatest(0, c.voice_seconds_limit - c.voice_seconds_used)
        end;
        allowance_exhausted := c.voice_seconds_limit is not null
            and voice_seconds_remaining <= 0;
        lease_expires_at := r.lease_expires_at;
        prepaid_seconds := r.prepaid_seconds;
        already_ended := v_action = 'END';
        if v_action = 'END' then
            applied := true;
        else
            denial_reason := 'SESSION_ENDED';
        end if;
        return next;
        return;
    end if;

    if v_action = 'OFFER' and (
        r.status <> 'ACTIVE' or upper(coalesce(p_target_platform, '')) not in ('WINDOWS', 'ANDROID')
    ) then
        denial_reason := 'HANDOVER_UNAVAILABLE';
        session_state := r.status;
        lease_expires_at := r.lease_expires_at;
        return next;
        return;
    end if;
    if v_action = 'CLAIM' and (
        (r.status <> 'HANDOVER_REQUESTED' and not r.auto_handover)
        or upper(coalesce(p_new_platform, '')) not in ('WINDOWS', 'ANDROID')
        or char_length(trim(coalesce(p_new_device_id, ''))) not between 8 and 128
        or coalesce(p_new_lease_token_hash, '') !~ '^[0-9a-f]{64}$'
        or (
            r.handover_target is not null
            and r.handover_target <> upper(p_new_platform)
        )
    ) then
        denial_reason := 'HANDOVER_UNAVAILABLE';
        session_state := r.status;
        lease_expires_at := r.lease_expires_at;
        return next;
        return;
    end if;

    v_expired := v_now > r.lease_expires_at + interval '5 minutes';
    v_elapsed := greatest(
        0,
        least(
            90,
            floor(extract(epoch from (v_now - coalesce(r.metered_at, r.updated_at, r.created_at))))::integer
        )
    );
    v_prepaid_used := least(greatest(0, r.prepaid_seconds), v_elapsed);
    v_prepaid_left := greatest(0, r.prepaid_seconds - v_prepaid_used);
    v_billable := greatest(0, v_elapsed - v_prepaid_used);

    if c.voice_seconds_limit is null then
        v_db_remaining := null;
        v_new_charge := 0;
    else
        v_db_remaining := greatest(0, c.voice_seconds_limit - c.voice_seconds_used);
        v_new_charge := least(v_billable, v_db_remaining);
        if v_new_charge > 0 then
            update public.lj_usage_cycles as cycle
               set voice_seconds_used = cycle.voice_seconds_used + v_new_charge,
                   updated_at = v_now
             where cycle.user_id = p_user_id and cycle.cycle_start = c.cycle_start
             returning * into c;
        end if;
        v_db_remaining := greatest(0, c.voice_seconds_limit - c.voice_seconds_used);
    end if;

    v_effective_remaining := case
        when c.voice_seconds_limit is null then null
        else v_db_remaining + v_prepaid_left
    end;
    allowance_exhausted := c.voice_seconds_limit is not null
        and coalesce(v_effective_remaining, 0) <= 0;

    if v_action = 'END' or v_expired or allowance_exhausted then
        v_new_status := 'ENDED';
        v_expiry := v_now;
    elsif v_action = 'OFFER' then
        v_new_status := 'HANDOVER_REQUESTED';
        v_expiry := v_now + interval '90 seconds';
    else
        v_new_status := 'ACTIVE';
        v_expiry := v_now + interval '90 seconds';
    end if;

    update public.lj_voice_sessions as voice
       set status = v_new_status,
           active_device_id = case
               when v_action = 'CLAIM' and v_new_status = 'ACTIVE' then trim(p_new_device_id)
               else voice.active_device_id
           end,
           active_platform = case
               when v_action = 'CLAIM' and v_new_status = 'ACTIVE' then upper(p_new_platform)
               else voice.active_platform
           end,
           lease_token_hash = case
               when v_action = 'CLAIM' and v_new_status = 'ACTIVE' then p_new_lease_token_hash
               else voice.lease_token_hash
           end,
           handover_target = case
               when v_action = 'OFFER' and v_new_status <> 'ENDED' then upper(p_target_platform)
               when v_action in ('CLAIM', 'END') or v_new_status = 'ENDED' then null
               else voice.handover_target
           end,
           transcript_tail = case
               when p_transcript_tail is null then voice.transcript_tail
               else p_transcript_tail
           end,
           last_voice_state = case
               when p_voice_state is null then voice.last_voice_state
               else upper(p_voice_state)
           end,
           prepaid_seconds = v_prepaid_left,
           metered_at = v_now,
           lease_expires_at = v_expiry,
           updated_at = v_now
     where voice.id = r.id and voice.user_id = p_user_id;

    applied := v_action = 'END' or (not v_expired and (
        v_action = 'HEARTBEAT'
        or (v_action in ('OFFER', 'CLAIM') and not allowance_exhausted)
    ));
    if v_expired and v_action <> 'END' then
        denial_reason := 'LEASE_EXPIRED';
    elsif allowance_exhausted and v_action in ('OFFER', 'CLAIM') then
        denial_reason := 'ALLOWANCE_EXHAUSTED';
    end if;
    session_state := v_new_status;
    seconds_charged := v_new_charge;
    voice_seconds_remaining := case
        when c.voice_seconds_limit is null then null
        when v_new_status = 'ENDED' then v_db_remaining
        else v_effective_remaining
    end;
    lease_expires_at := v_expiry;
    prepaid_seconds := v_prepaid_left;
    already_ended := false;
    return next;
end
$$;

-- Create (or validate) a live device-bound lease before a Realtime client
-- secret can be returned. This is serialized per account and respects the
-- single-live-session index, while old clients may still call /voice/start
-- immediately afterward and receive their usual lease token.
drop function if exists public.ensure_lj_realtime_lease(uuid,text,text,text,text,text);
create or replace function public.ensure_lj_realtime_lease(
    p_user_id uuid,
    p_device_id text,
    p_platform text,
    p_conversation_id text,
    p_proposed_session_id text,
    p_proposed_lease_token_hash text
)
returns table(
    allowed boolean,
    denial_reason text,
    session_id text,
    lease_created boolean,
    session_state text,
    voice_seconds_remaining integer,
    lease_expires_at timestamptz
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    r public.lj_voice_sessions%rowtype;
    c public.lj_usage_cycles%rowtype;
    ended record;
    v_now timestamptz := clock_timestamp();
    v_has_live boolean := false;
begin
    allowed := false;
    denial_reason := '';
    lease_created := false;
    if char_length(trim(coalesce(p_device_id, ''))) not between 8 and 128
       or upper(coalesce(p_platform, '')) not in ('WINDOWS', 'ANDROID')
       or char_length(trim(coalesce(p_proposed_session_id, ''))) not between 8 and 100
       or coalesce(p_proposed_lease_token_hash, '') !~ '^[0-9a-f]{64}$' then
        denial_reason := 'INVALID_REQUEST';
        return next;
        return;
    end if;
    if p_conversation_id is not null and not exists (
        select 1 from public.lj_conversations as conversation
         where conversation.id = p_conversation_id and conversation.user_id = p_user_id
    ) then
        denial_reason := 'CONVERSATION_NOT_FOUND';
        return next;
        return;
    end if;

    perform pg_advisory_xact_lock(hashtextextended(p_user_id::text, 159701));
    select voice.* into r
      from public.lj_voice_sessions as voice
     where voice.user_id = p_user_id
       and voice.status in ('ACTIVE', 'HANDOVER_REQUESTED')
     order by voice.updated_at desc, voice.id desc
     limit 1
     for update;
    v_has_live := found;

    -- A prior request that never returned a secret must not leave a temporary
    -- lease blocking this device. Abort it without charging, then create a new
    -- exact-token pending lease for this issuance attempt.
    if v_has_live and r.issuance_pending then
        if r.active_device_id <> trim(p_device_id) and v_now <= r.lease_expires_at then
            denial_reason := 'OTHER_DEVICE_ACTIVE';
            session_id := r.id;
            session_state := r.status;
            lease_expires_at := r.lease_expires_at;
            return next;
            return;
        end if;
        select * into ended
          from public.apply_lj_voice_session(
              p_user_id, r.id, r.active_device_id, r.lease_token_hash,
              'ABORT', null, null, null, null, null, null
          );
        if not coalesce(ended.applied, false) then
            denial_reason := 'LEASE_UNAVAILABLE';
            return next;
            return;
        end if;
        v_has_live := false;
    end if;

    -- A client-secret mint must never revive a lease whose 90-second billing
    -- window has expired. Reconnect/claim routes retain their separate grace
    -- policy, but token issuance closes this row and starts a fresh lease.
    if v_has_live and v_now <= r.lease_expires_at then
        if r.active_device_id <> trim(p_device_id) then
            denial_reason := 'OTHER_DEVICE_ACTIVE';
            session_id := r.id;
            session_state := r.status;
            lease_expires_at := r.lease_expires_at;
            return next;
            return;
        end if;
        c := public.ensure_lj_usage_cycle(p_user_id);
        if c.voice_seconds_limit is not null
           and c.voice_seconds_used >= c.voice_seconds_limit
           and r.prepaid_seconds <= 0 then
            denial_reason := 'ALLOWANCE_EXHAUSTED';
            session_id := r.id;
            session_state := r.status;
            voice_seconds_remaining := 0;
            lease_expires_at := r.lease_expires_at;
            return next;
            return;
        end if;
        allowed := true;
        session_id := r.id;
        lease_created := false;
        session_state := r.status;
        voice_seconds_remaining := case
            when c.voice_seconds_limit is null then null
            else greatest(0, c.voice_seconds_limit - c.voice_seconds_used) + r.prepaid_seconds
        end;
        lease_expires_at := r.lease_expires_at;
        return next;
        return;
    elsif v_has_live then
        select * into ended
          from public.apply_lj_voice_session(
              p_user_id, r.id, r.active_device_id, r.lease_token_hash,
              'END', null, null, null, null, null, null
          );
    end if;

    c := public.ensure_lj_usage_cycle(p_user_id);
    if c.voice_seconds_limit is not null
       and c.voice_seconds_used >= c.voice_seconds_limit then
        denial_reason := 'ALLOWANCE_EXHAUSTED';
        voice_seconds_remaining := 0;
        return next;
        return;
    end if;

    insert into public.lj_voice_sessions(
        id, user_id, conversation_id, active_device_id, active_platform,
        status, auto_handover, transcript_tail, last_voice_state,
        lease_token_hash, lease_expires_at, metered_at, prepaid_seconds,
        issuance_pending,
        created_at, updated_at
    ) values (
        trim(p_proposed_session_id), p_user_id, p_conversation_id,
        trim(p_device_id), upper(p_platform), 'ACTIVE', false, '[]'::jsonb,
        'IDLE', p_proposed_lease_token_hash, v_now + interval '90 seconds',
        v_now, 0, true, v_now, v_now
    );
    allowed := true;
    session_id := trim(p_proposed_session_id);
    lease_created := true;
    session_state := 'ACTIVE';
    voice_seconds_remaining := case
        when c.voice_seconds_limit is null then null
        else greatest(0, c.voice_seconds_limit - c.voice_seconds_used)
    end;
    lease_expires_at := v_now + interval '90 seconds';
    return next;
end
$$;

-- Every returned Realtime client secret reserves a small, non-refundable
-- minimum. The credit is consumed before heartbeat metering adds more time,
-- preventing both free token minting and double-charging the first interval.
drop function if exists public.reserve_lj_realtime_token(uuid,text,text,integer);
create or replace function public.reserve_lj_realtime_token(
    p_user_id uuid,
    p_session_id text,
    p_device_id text,
    p_seconds integer default 15
)
returns table(
    allowed boolean,
    denial_reason text,
    reserved_seconds integer,
    voice_seconds_remaining integer,
    lease_expires_at timestamptz
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    r public.lj_voice_sessions%rowtype;
    c public.lj_usage_cycles%rowtype;
    v_now timestamptz := clock_timestamp();
    v_available integer;
    v_reserve integer := 0;
begin
    allowed := false;
    denial_reason := '';
    reserved_seconds := 0;
    if p_seconds not between 1 and 90 then
        denial_reason := 'INVALID_REQUEST';
        return next;
        return;
    end if;
    perform pg_advisory_xact_lock(hashtextextended(p_user_id::text, 159701));
    select voice.* into r
      from public.lj_voice_sessions as voice
     where voice.id = trim(coalesce(p_session_id, ''))
       and voice.user_id = p_user_id
       and voice.active_device_id = trim(coalesce(p_device_id, ''))
       and voice.status in ('ACTIVE', 'HANDOVER_REQUESTED')
     for update;
    if not found or v_now > r.lease_expires_at then
        denial_reason := 'LEASE_UNAVAILABLE';
        return next;
        return;
    end if;

    c := public.ensure_lj_usage_cycle(p_user_id);
    if c.voice_seconds_limit is not null then
        v_available := greatest(0, c.voice_seconds_limit - c.voice_seconds_used);
        if v_available <= 0 then
            denial_reason := 'ALLOWANCE_EXHAUSTED';
            voice_seconds_remaining := r.prepaid_seconds;
            lease_expires_at := r.lease_expires_at;
            return next;
            return;
        end if;
        v_reserve := least(p_seconds, v_available);
        update public.lj_usage_cycles as cycle
           set voice_seconds_used = cycle.voice_seconds_used + v_reserve,
               updated_at = v_now
         where cycle.user_id = p_user_id and cycle.cycle_start = c.cycle_start
         returning * into c;
    end if;

    update public.lj_voice_sessions as voice
       set prepaid_seconds = least(86400, voice.prepaid_seconds + v_reserve),
           issuance_pending = false,
           lease_expires_at = v_now + interval '90 seconds',
           updated_at = v_now
     where voice.id = r.id and voice.user_id = p_user_id
     returning voice.lease_expires_at, voice.prepaid_seconds
          into lease_expires_at, r.prepaid_seconds;
    allowed := true;
    reserved_seconds := v_reserve;
    voice_seconds_remaining := case
        when c.voice_seconds_limit is null then null
        else greatest(0, c.voice_seconds_limit - c.voice_seconds_used) + r.prepaid_seconds
    end;
    return next;
end
$$;

-- Meter standalone transcription/TTS calls. When a live lease exists, the
-- charge becomes prepaid lease time so the next heartbeat consumes that credit
-- instead of charging the same interval twice.
drop function if exists public.reserve_lj_voice_tool_usage(uuid,text,integer);
create or replace function public.reserve_lj_voice_tool_usage(
    p_user_id uuid,
    p_device_id text,
    p_seconds integer
)
returns table(
    allowed boolean,
    denial_reason text,
    reserved_seconds integer,
    voice_seconds_remaining integer,
    session_id text
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    r public.lj_voice_sessions%rowtype;
    c public.lj_usage_cycles%rowtype;
    v_now timestamptz := clock_timestamp();
    v_available integer;
    v_has_session boolean := false;
    v_prepaid_after integer := 0;
begin
    allowed := false;
    denial_reason := '';
    reserved_seconds := 0;
    if p_seconds not between 1 and 600
       or char_length(trim(coalesce(p_device_id, ''))) not between 8 and 128 then
        denial_reason := 'INVALID_REQUEST';
        return next;
        return;
    end if;
    perform pg_advisory_xact_lock(hashtextextended(p_user_id::text, 159701));
    select voice.* into r
      from public.lj_voice_sessions as voice
     where voice.user_id = p_user_id
       and voice.active_device_id = trim(p_device_id)
       and voice.status in ('ACTIVE', 'HANDOVER_REQUESTED')
       and v_now <= voice.lease_expires_at
     order by voice.updated_at desc, voice.id desc
     limit 1
     for update;
    v_has_session := found;

    c := public.ensure_lj_usage_cycle(p_user_id);
    if c.voice_seconds_limit is not null then
        v_available := greatest(0, c.voice_seconds_limit - c.voice_seconds_used);
        if v_available < p_seconds then
            denial_reason := 'ALLOWANCE_EXHAUSTED';
            voice_seconds_remaining := v_available + case when v_has_session then r.prepaid_seconds else 0 end;
            session_id := case when v_has_session then r.id else null end;
            return next;
            return;
        end if;
        update public.lj_usage_cycles as cycle
           set voice_seconds_used = cycle.voice_seconds_used + p_seconds,
               updated_at = v_now
         where cycle.user_id = p_user_id and cycle.cycle_start = c.cycle_start
         returning * into c;
        if v_has_session then
            update public.lj_voice_sessions as voice
               set prepaid_seconds = least(86400, voice.prepaid_seconds + p_seconds),
                   updated_at = v_now
             where voice.id = r.id and voice.user_id = p_user_id
             returning voice.prepaid_seconds into v_prepaid_after;
        end if;
    end if;

    allowed := true;
    reserved_seconds := case when c.voice_seconds_limit is null then 0 else p_seconds end;
    session_id := r.id;
    voice_seconds_remaining := case
        when c.voice_seconds_limit is null then null
        else greatest(0, c.voice_seconds_limit - c.voice_seconds_used)
             + case when v_has_session then v_prepaid_after else 0 end
    end;
    return next;
end
$$;

revoke all on function public.reserve_lj_chat_usage(uuid,text,text,text) from public, anon, authenticated;
revoke all on function public.set_lj_memory_enabled(uuid,boolean) from public, anon, authenticated;
revoke all on function public.replace_lj_skill_triggers(uuid,uuid,jsonb) from public, anon, authenticated;
revoke all on function public.refund_lj_chat_usage(uuid,text,text) from public, anon, authenticated;
revoke all on function public.complete_lj_chat_usage(uuid,text,text) from public, anon, authenticated;
revoke all on function public.save_lj_chat_turn(uuid,text,text,text,text,text,text,text) from public, anon, authenticated;
revoke all on function public.delete_lj_conversation(uuid,text) from public, anon, authenticated;
revoke all on function public.apply_lj_voice_session(uuid,text,text,text,text,jsonb,text,text,text,text,text) from public, anon, authenticated;
revoke all on function public.ensure_lj_realtime_lease(uuid,text,text,text,text,text) from public, anon, authenticated;
revoke all on function public.reserve_lj_realtime_token(uuid,text,text,integer) from public, anon, authenticated;
revoke all on function public.reserve_lj_voice_tool_usage(uuid,text,integer) from public, anon, authenticated;
revoke all on function public.register_lj_device_attempt(uuid,text,text,text,text,text,timestamptz,integer) from public, anon, authenticated;
revoke all on function public.revoke_lj_device_session(uuid,text,text) from public, anon, authenticated;
grant execute on function public.reserve_lj_chat_usage(uuid,text,text,text) to service_role;
grant execute on function public.set_lj_memory_enabled(uuid,boolean) to service_role;
grant execute on function public.replace_lj_skill_triggers(uuid,uuid,jsonb) to service_role;
grant execute on function public.refund_lj_chat_usage(uuid,text,text) to service_role;
grant execute on function public.complete_lj_chat_usage(uuid,text,text) to service_role;
grant execute on function public.save_lj_chat_turn(uuid,text,text,text,text,text,text,text) to service_role;
grant execute on function public.delete_lj_conversation(uuid,text) to service_role;
grant execute on function public.apply_lj_voice_session(uuid,text,text,text,text,jsonb,text,text,text,text,text) to service_role;
grant execute on function public.ensure_lj_realtime_lease(uuid,text,text,text,text,text) to service_role;
grant execute on function public.reserve_lj_realtime_token(uuid,text,text,integer) to service_role;
grant execute on function public.reserve_lj_voice_tool_usage(uuid,text,integer) to service_role;
grant execute on function public.register_lj_device_attempt(uuid,text,text,text,text,text,timestamptz,integer) to service_role;
grant execute on function public.revoke_lj_device_session(uuid,text,text) to service_role;

commit;
