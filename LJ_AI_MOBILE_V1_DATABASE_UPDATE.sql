-- LJ AI Mobile V1 staging schema
-- Review in a staging Supabase project before running against production.
-- This file does not change the existing two-device account limit.

begin;

create table if not exists public.device_pairing_codes (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users(id) on delete cascade,
    windows_device_id text not null check (char_length(windows_device_id) between 8 and 128),
    windows_device_name text not null check (char_length(windows_device_name) between 1 and 80),
    code_hash text not null unique check (code_hash ~ '^[0-9a-f]{64}$'),
    expires_at timestamptz not null,
    created_at timestamptz not null default now(),
    claimed_at timestamptz,
    claimed_by_device_id text
);

create index if not exists device_pairing_codes_owner_idx
    on public.device_pairing_codes(user_id, expires_at desc);

create table if not exists public.device_links (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users(id) on delete cascade,
    windows_device_id text not null check (char_length(windows_device_id) between 8 and 128),
    windows_device_name text not null check (char_length(windows_device_name) between 1 and 80),
    mobile_device_id text not null check (char_length(mobile_device_id) between 8 and 128),
    mobile_device_name text not null check (char_length(mobile_device_name) between 1 and 80),
    is_active boolean not null default true,
    created_at timestamptz not null default now(),
    last_used_at timestamptz not null default now(),
    revoked_at timestamptz,
    unique (user_id, windows_device_id, mobile_device_id),
    check (windows_device_id <> mobile_device_id)
);

create index if not exists device_links_owner_idx
    on public.device_links(user_id, last_used_at desc)
    where is_active = true;

create table if not exists public.device_remote_commands (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users(id) on delete cascade,
    link_id uuid not null references public.device_links(id) on delete cascade,
    source_device_id text not null,
    target_device_id text not null,
    action text not null check (action in (
        'show_notification', 'media_play_pause', 'media_next', 'volume_mute',
        'lock_pc', 'open_lj_ai', 'run_diagnostic'
    )),
    payload jsonb not null default '{}'::jsonb,
    requires_pc_confirmation boolean not null default false,
    status text not null default 'PENDING' check (status in ('PENDING', 'DELIVERED', 'SUCCEEDED', 'FAILED', 'EXPIRED')),
    result jsonb,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    delivered_at timestamptz,
    completed_at timestamptz
);

create index if not exists device_remote_commands_pending_idx
    on public.device_remote_commands(target_device_id, created_at)
    where status in ('PENDING', 'DELIVERED');

create table if not exists public.smartthings_oauth_states (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users(id) on delete cascade,
    mobile_device_id text not null,
    state_hash text not null unique check (state_hash ~ '^[0-9a-f]{64}$'),
    expires_at timestamptz not null,
    created_at timestamptz not null default now(),
    completed_at timestamptz
);

create table if not exists public.smartthings_connections (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null unique references auth.users(id) on delete cascade,
    access_token_ciphertext text not null,
    refresh_token_ciphertext text,
    token_expires_at timestamptz,
    scopes text[] not null default '{}',
    is_active boolean not null default true,
    connected_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    revoked_at timestamptz
);

alter table public.device_pairing_codes enable row level security;
alter table public.device_links enable row level security;
alter table public.device_remote_commands enable row level security;
alter table public.smartthings_oauth_states enable row level security;
alter table public.smartthings_connections enable row level security;

revoke all on public.device_pairing_codes from anon, authenticated;
revoke all on public.device_links from anon, authenticated;
revoke all on public.device_remote_commands from anon, authenticated;
revoke all on public.smartthings_oauth_states from anon, authenticated;
revoke all on public.smartthings_connections from anon, authenticated;

grant all on public.device_pairing_codes to service_role;
grant all on public.device_links to service_role;
grant all on public.device_remote_commands to service_role;
grant all on public.smartthings_oauth_states to service_role;
grant all on public.smartthings_connections to service_role;

-- Claims a one-time code and creates/reactivates the device link atomically.
create or replace function public.claim_lj_pairing_code(
    p_user_id uuid,
    p_code_hash text,
    p_mobile_device_id text,
    p_mobile_device_name text
)
returns table(allowed boolean, link_id uuid, windows_device_name text)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_code public.device_pairing_codes%rowtype;
    v_link_id uuid;
    v_mobile_active boolean;
    v_windows_active boolean;
begin
    if p_user_id is null
       or p_code_hash !~ '^[0-9a-f]{64}$'
       or p_mobile_device_id !~ '^[A-Za-z0-9_.:-]{8,128}$' then
        return query select false, null::uuid, null::text;
        return;
    end if;

    select * into v_code
      from public.device_pairing_codes
     where user_id = p_user_id
       and code_hash = p_code_hash
       and claimed_at is null
       and expires_at > now()
     for update;

    if not found or v_code.windows_device_id = p_mobile_device_id then
        return query select false, null::uuid, null::text;
        return;
    end if;

    select exists(
        select 1 from public.account_devices
         where user_id = p_user_id and device_id = p_mobile_device_id and is_active = true
    ) into v_mobile_active;
    select exists(
        select 1 from public.account_devices
         where user_id = p_user_id and device_id = v_code.windows_device_id and is_active = true
    ) into v_windows_active;

    if not v_mobile_active or not v_windows_active then
        return query select false, null::uuid, null::text;
        return;
    end if;

    insert into public.device_links (
        user_id, windows_device_id, windows_device_name,
        mobile_device_id, mobile_device_name, is_active, last_used_at, revoked_at
    ) values (
        p_user_id, v_code.windows_device_id, v_code.windows_device_name,
        p_mobile_device_id, left(coalesce(nullif(trim(p_mobile_device_name), ''), 'Android phone'), 80),
        true, now(), null
    )
    on conflict (user_id, windows_device_id, mobile_device_id) do update
       set windows_device_name = excluded.windows_device_name,
           mobile_device_name = excluded.mobile_device_name,
           is_active = true,
           last_used_at = now(),
           revoked_at = null
    returning id into v_link_id;

    update public.device_pairing_codes
       set claimed_at = now(), claimed_by_device_id = p_mobile_device_id
     where id = v_code.id;

    return query select true, v_link_id, v_code.windows_device_name;
end;
$$;

revoke all on function public.claim_lj_pairing_code(uuid, text, text, text)
    from public, anon, authenticated;
grant execute on function public.claim_lj_pairing_code(uuid, text, text, text)
    to service_role;

commit;
