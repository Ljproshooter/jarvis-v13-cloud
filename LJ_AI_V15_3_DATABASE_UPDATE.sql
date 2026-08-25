-- LJ AI V15.3 two-device account security update
-- Run once in Supabase -> SQL Editor before deploying the V15.3 cloud files.
-- Safe to run again. It does not delete accounts, tickets, news, community posts or chat logs.

begin;

create table if not exists public.account_devices (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users(id) on delete cascade,
    device_id text not null check (char_length(device_id) between 8 and 128),
    device_name text not null default 'LJ AI device' check (char_length(device_name) between 1 and 80),
    platform text not null default 'Unknown platform' check (char_length(platform) between 1 and 80),
    device_token_hash text not null check (device_token_hash ~ '^[0-9a-f]{64}$'),
    is_active boolean not null default true,
    created_at timestamptz not null default now(),
    last_seen_at timestamptz not null default now(),
    revoked_at timestamptz,
    unique (user_id, device_id)
);

create index if not exists account_devices_active_user_idx
    on public.account_devices(user_id, last_seen_at desc)
    where is_active = true;

alter table public.account_devices enable row level security;
revoke all on public.account_devices from anon, authenticated;
grant all on public.account_devices to service_role;

-- The advisory lock makes two simultaneous new-device logins count as one
-- transaction at a time, so a third device cannot slip through a race.
create or replace function public.register_lj_device(
    p_user_id uuid,
    p_device_id text,
    p_device_name text,
    p_platform text,
    p_token_hash text,
    p_max_devices integer default 2
)
returns table(allowed boolean, active_devices integer)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_existing_active boolean;
    v_existing_found boolean := false;
    v_active_count integer := 0;
begin
    if p_user_id is null
       or p_device_id is null
       or p_device_id !~ '^[A-Za-z0-9_.:-]{8,128}$'
       or p_token_hash is null
       or p_token_hash !~ '^[0-9a-f]{64}$'
       or p_max_devices is null
       or p_max_devices < 1
       or p_max_devices > 10 then
        return query select false, 0;
        return;
    end if;

    perform pg_advisory_xact_lock(hashtext(p_user_id::text));

    select d.is_active
      into v_existing_active
      from public.account_devices as d
     where d.user_id = p_user_id and d.device_id = p_device_id
     for update;
    v_existing_found := found;

    if v_existing_found and v_existing_active then
        update public.account_devices
           set device_name = left(coalesce(nullif(trim(p_device_name), ''), 'LJ AI device'), 80),
               platform = left(coalesce(nullif(trim(p_platform), ''), 'Unknown platform'), 80),
               device_token_hash = p_token_hash,
               last_seen_at = now(),
               revoked_at = null
         where user_id = p_user_id and device_id = p_device_id;

        select count(*)::integer
          into v_active_count
          from public.account_devices
         where user_id = p_user_id and is_active = true;
        return query select true, v_active_count;
        return;
    end if;

    select count(*)::integer
      into v_active_count
      from public.account_devices
     where user_id = p_user_id and is_active = true;

    if v_active_count >= p_max_devices then
        return query select false, v_active_count;
        return;
    end if;

    insert into public.account_devices (
        user_id, device_id, device_name, platform, device_token_hash,
        is_active, created_at, last_seen_at, revoked_at
    ) values (
        p_user_id,
        p_device_id,
        left(coalesce(nullif(trim(p_device_name), ''), 'LJ AI device'), 80),
        left(coalesce(nullif(trim(p_platform), ''), 'Unknown platform'), 80),
        p_token_hash,
        true,
        now(),
        now(),
        null
    )
    on conflict (user_id, device_id) do update
       set device_name = excluded.device_name,
           platform = excluded.platform,
           device_token_hash = excluded.device_token_hash,
           is_active = true,
           last_seen_at = now(),
           revoked_at = null;

    select count(*)::integer
      into v_active_count
      from public.account_devices
     where user_id = p_user_id and is_active = true;
    return query select true, v_active_count;
end;
$$;

revoke all on function public.register_lj_device(uuid, text, text, text, text, integer)
    from public, anon, authenticated;
grant execute on function public.register_lj_device(uuid, text, text, text, text, integer)
    to service_role;

commit;

select count(*) as registered_devices_ready
from public.account_devices;
