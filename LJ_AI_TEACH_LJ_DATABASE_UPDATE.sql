-- Teach LJ: safe Learning-by-Demonstration storage and run state.
-- Additive migration. Run once in the production Supabase SQL Editor before
-- deploying teach_lj_routes.py. Clients never receive direct table access.

begin;

create table if not exists public.lj_skills (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users(id) on delete cascade,
    name text not null check (char_length(trim(name)) between 1 and 80),
    description text not null default '' check (char_length(description) <= 500),
    enabled boolean not null default true,
    current_version integer not null default 1 check (current_version >= 1),
    variables_schema jsonb not null default '[]'::jsonb
        check (jsonb_typeof(variables_schema) = 'array'),
    required_apps jsonb not null default '[]'::jsonb
        check (jsonb_typeof(required_apps) = 'array'),
    required_sites jsonb not null default '[]'::jsonb
        check (jsonb_typeof(required_sites) = 'array'),
    safety_policy jsonb not null default '{"auto_approve_actions":[],"confirm_target_keywords":true}'::jsonb
        check (jsonb_typeof(safety_policy) = 'object'),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    last_used_at timestamptz,
    last_run_at timestamptz,
    last_run_status text check (last_run_status is null or last_run_status in (
        'READY', 'WAITING_CONFIRMATION', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED'
    )),
    deleted_at timestamptz,
    unique (id, user_id)
);

create unique index if not exists lj_skills_owner_name_idx
    on public.lj_skills(user_id, lower(name))
    where deleted_at is null;

create index if not exists lj_skills_owner_updated_idx
    on public.lj_skills(user_id, updated_at desc)
    where deleted_at is null;

create table if not exists public.lj_skill_versions (
    id uuid primary key default gen_random_uuid(),
    skill_id uuid not null,
    user_id uuid not null references auth.users(id) on delete cascade,
    version integer not null check (version >= 1),
    variables_schema jsonb not null default '[]'::jsonb
        check (jsonb_typeof(variables_schema) = 'array'),
    required_apps jsonb not null default '[]'::jsonb
        check (jsonb_typeof(required_apps) = 'array'),
    required_sites jsonb not null default '[]'::jsonb
        check (jsonb_typeof(required_sites) = 'array'),
    safety_policy jsonb not null default '{"auto_approve_actions":[],"confirm_target_keywords":true}'::jsonb
        check (jsonb_typeof(safety_policy) = 'object'),
    steps jsonb not null check (jsonb_typeof(steps) = 'array' and jsonb_array_length(steps) between 1 and 100),
    change_note text not null default '' check (char_length(change_note) <= 240),
    created_by_device_id text,
    created_at timestamptz not null default now(),
    unique(skill_id, version),
    unique(skill_id, version, user_id),
    foreign key (skill_id, user_id)
        references public.lj_skills(id, user_id) on delete cascade
);

create index if not exists lj_skill_versions_owner_idx
    on public.lj_skill_versions(user_id, skill_id, version desc);

create table if not exists public.lj_skill_runs (
    id uuid primary key default gen_random_uuid(),
    skill_id uuid not null,
    skill_version integer not null,
    user_id uuid not null references auth.users(id) on delete cascade,
    device_id text not null check (char_length(device_id) between 8 and 128),
    mode text not null check (mode in ('TEST', 'EXECUTE')),
    status text not null check (status in (
        'READY', 'WAITING_CONFIRMATION', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED'
    )),
    state_version bigint not null default 0 check (state_version >= 0),
    variables jsonb not null default '{}'::jsonb check (jsonb_typeof(variables) = 'object'),
    current_step_index integer not null default 0 check (current_step_index >= 0),
    pending_confirmation jsonb check (
        pending_confirmation is null or jsonb_typeof(pending_confirmation) = 'object'
    ),
    confirmation_token_hash text check (
        confirmation_token_hash is null or confirmation_token_hash ~ '^[0-9a-f]{64}$'
    ),
    confirmation_expires_at timestamptz,
    error_message text check (error_message is null or char_length(error_message) <= 500),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    completed_at timestamptz,
    unique (id, skill_id, user_id),
    foreign key (skill_id, skill_version, user_id)
        references public.lj_skill_versions(skill_id, version, user_id) on delete restrict,
    check (
        (
            status = 'WAITING_CONFIRMATION'
            and pending_confirmation is not null
            and confirmation_token_hash is not null
            and confirmation_expires_at is not null
        )
        or
        (
            status <> 'WAITING_CONFIRMATION'
            and pending_confirmation is null
            and confirmation_token_hash is null
            and confirmation_expires_at is null
        )
    )
);

-- Keep the migration additive when an earlier Teach LJ draft created tables.
alter table public.lj_skill_runs
    add column if not exists state_version bigint not null default 0;

create index if not exists lj_skill_runs_owner_idx
    on public.lj_skill_runs(user_id, created_at desc);

create index if not exists lj_skill_runs_version_idx
    on public.lj_skill_runs(skill_id, skill_version);

create index if not exists lj_skill_runs_active_idx
    on public.lj_skill_runs(user_id, device_id, updated_at desc)
    where status in ('READY', 'WAITING_CONFIRMATION', 'RUNNING');

create table if not exists public.lj_skill_run_events (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users(id) on delete cascade,
    skill_id uuid not null,
    run_id uuid not null,
    event_type text not null check (char_length(event_type) between 1 and 80),
    step_index integer check (step_index is null or step_index >= 0),
    details jsonb not null default '{}'::jsonb check (jsonb_typeof(details) = 'object'),
    created_at timestamptz not null default now(),
    foreign key (run_id, skill_id, user_id)
        references public.lj_skill_runs(id, skill_id, user_id) on delete cascade
);

create index if not exists lj_skill_run_events_owner_idx
    on public.lj_skill_run_events(user_id, skill_id, created_at desc);

create index if not exists lj_skill_run_events_run_idx
    on public.lj_skill_run_events(run_id, created_at);

create or replace function public.valid_lj_skill_safety_policy(policy jsonb)
returns boolean
language sql
immutable
set search_path = public, pg_temp
as $$
    select case
        when jsonb_typeof(policy) <> 'object'
          or jsonb_typeof(policy->'auto_approve_actions') <> 'array'
          or jsonb_typeof(policy->'confirm_target_keywords') <> 'boolean'
          or policy->'confirm_target_keywords' <> 'true'::jsonb
        then false
        else jsonb_array_length(policy->'auto_approve_actions') = 0
    end;
$$;

-- Retire any older opt-out policy before enforcing the no-auto-approval rule.
drop trigger if exists lj_skill_versions_immutable_update on public.lj_skill_versions;

update public.lj_skills
   set safety_policy = '{"auto_approve_actions":[],"confirm_target_keywords":true}'::jsonb,
       updated_at = now()
 where not public.valid_lj_skill_safety_policy(safety_policy);

update public.lj_skill_versions
   set safety_policy = '{"auto_approve_actions":[],"confirm_target_keywords":true}'::jsonb
 where not public.valid_lj_skill_safety_policy(safety_policy);

alter table public.lj_skills
  drop constraint if exists lj_skills_safe_policy_check;
alter table public.lj_skills
  add constraint lj_skills_safe_policy_check
  check (public.valid_lj_skill_safety_policy(safety_policy));

alter table public.lj_skill_versions
  drop constraint if exists lj_skill_versions_safe_policy_check;
alter table public.lj_skill_versions
  add constraint lj_skill_versions_safe_policy_check
  check (public.valid_lj_skill_safety_policy(safety_policy));

alter table public.lj_skill_runs
  drop constraint if exists lj_skill_runs_state_version_check;
alter table public.lj_skill_runs
  add constraint lj_skill_runs_state_version_check check (state_version >= 0);

-- Creation is transactional so a Skill can never exist without version 1.
create or replace function public.create_lj_skill(
    p_user_id uuid,
    p_name text,
    p_description text,
    p_enabled boolean,
    p_variables_schema jsonb,
    p_required_apps jsonb,
    p_required_sites jsonb,
    p_safety_policy jsonb,
    p_steps jsonb,
    p_change_note text default 'Initial demonstration',
    p_device_id text default null
)
returns table(skill_id uuid, version integer)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_skill_id uuid;
begin
    if p_user_id is null
       or char_length(trim(coalesce(p_name, ''))) not between 1 and 80
       or jsonb_typeof(coalesce(p_variables_schema, '[]'::jsonb)) <> 'array'
       or jsonb_typeof(coalesce(p_required_apps, '[]'::jsonb)) <> 'array'
       or jsonb_typeof(coalesce(p_required_sites, '[]'::jsonb)) <> 'array'
       or not public.valid_lj_skill_safety_policy(
           coalesce(p_safety_policy, '{"auto_approve_actions":[],"confirm_target_keywords":true}'::jsonb)
       )
       or jsonb_typeof(coalesce(p_steps, '[]'::jsonb)) <> 'array'
       or jsonb_array_length(coalesce(p_steps, '[]'::jsonb)) not between 1 and 100
       or char_length(coalesce(p_description, '')) > 500
       or char_length(coalesce(p_change_note, '')) > 240 then
        raise exception 'Invalid Teach LJ Skill payload';
    end if;

    insert into public.lj_skills (
        user_id, name, description, enabled, current_version,
        variables_schema, required_apps, required_sites, safety_policy
    ) values (
        p_user_id,
        trim(p_name),
        left(coalesce(p_description, ''), 500),
        coalesce(p_enabled, true),
        1,
        coalesce(p_variables_schema, '[]'::jsonb),
        coalesce(p_required_apps, '[]'::jsonb),
        coalesce(p_required_sites, '[]'::jsonb),
        coalesce(p_safety_policy, '{"auto_approve_actions":[],"confirm_target_keywords":true}'::jsonb)
    ) returning id into v_skill_id;

    insert into public.lj_skill_versions (
        skill_id, user_id, version, variables_schema, required_apps,
        required_sites, safety_policy, steps, change_note, created_by_device_id
    ) values (
        v_skill_id,
        p_user_id,
        1,
        coalesce(p_variables_schema, '[]'::jsonb),
        coalesce(p_required_apps, '[]'::jsonb),
        coalesce(p_required_sites, '[]'::jsonb),
        coalesce(p_safety_policy, '{"auto_approve_actions":[],"confirm_target_keywords":true}'::jsonb),
        p_steps,
        left(coalesce(p_change_note, ''), 240),
        nullif(trim(coalesce(p_device_id, '')), '')
    );

    return query select v_skill_id, 1;
end;
$$;

-- Edits append an immutable workflow version and update the list-view snapshot.
create or replace function public.create_lj_skill_version(
    p_user_id uuid,
    p_skill_id uuid,
    p_variables_schema jsonb,
    p_required_apps jsonb,
    p_required_sites jsonb,
    p_safety_policy jsonb,
    p_steps jsonb,
    p_change_note text default 'Workflow edited',
    p_device_id text default null
)
returns table(new_version integer)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_current integer;
    v_new integer;
begin
    if p_user_id is null
       or p_skill_id is null
       or jsonb_typeof(coalesce(p_variables_schema, '[]'::jsonb)) <> 'array'
       or jsonb_typeof(coalesce(p_required_apps, '[]'::jsonb)) <> 'array'
       or jsonb_typeof(coalesce(p_required_sites, '[]'::jsonb)) <> 'array'
       or not public.valid_lj_skill_safety_policy(
           coalesce(p_safety_policy, '{"auto_approve_actions":[],"confirm_target_keywords":true}'::jsonb)
       )
       or jsonb_typeof(coalesce(p_steps, '[]'::jsonb)) <> 'array'
       or jsonb_array_length(coalesce(p_steps, '[]'::jsonb)) not between 1 and 100
       or char_length(coalesce(p_change_note, '')) > 240 then
        raise exception 'Invalid Teach LJ Skill version payload';
    end if;

    select current_version into v_current
      from public.lj_skills
     where id = p_skill_id and user_id = p_user_id and deleted_at is null
     for update;
    if not found then
        raise exception 'Teach LJ Skill not found';
    end if;

    v_new := v_current + 1;
    insert into public.lj_skill_versions (
        skill_id, user_id, version, variables_schema, required_apps,
        required_sites, safety_policy, steps, change_note, created_by_device_id
    ) values (
        p_skill_id,
        p_user_id,
        v_new,
        coalesce(p_variables_schema, '[]'::jsonb),
        coalesce(p_required_apps, '[]'::jsonb),
        coalesce(p_required_sites, '[]'::jsonb),
        coalesce(p_safety_policy, '{"auto_approve_actions":[],"confirm_target_keywords":true}'::jsonb),
        p_steps,
        left(coalesce(p_change_note, ''), 240),
        nullif(trim(coalesce(p_device_id, '')), '')
    );

    update public.lj_skills
       set current_version = v_new,
           variables_schema = coalesce(p_variables_schema, '[]'::jsonb),
           required_apps = coalesce(p_required_apps, '[]'::jsonb),
           required_sites = coalesce(p_required_sites, '[]'::jsonb),
           safety_policy = coalesce(p_safety_policy, '{"auto_approve_actions":[],"confirm_target_keywords":true}'::jsonb),
           updated_at = now()
     where id = p_skill_id and user_id = p_user_id;

    return query select v_new;
end;
$$;

-- Start and bind a run atomically with a locked, non-deleted Skill. This
-- closes the race between a client starting a run and another device deleting
-- or disabling the Skill.
create or replace function public.start_lj_skill_run(
    p_user_id uuid,
    p_skill_id uuid,
    p_skill_version integer,
    p_device_id text,
    p_mode text,
    p_status text,
    p_variables jsonb,
    p_pending_confirmation jsonb default null,
    p_confirmation_token_hash text default null,
    p_confirmation_expires_at timestamptz default null
)
returns setof public.lj_skill_runs
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    skill_row public.lj_skills%rowtype;
begin
    if p_user_id is null
       or p_skill_id is null
       or p_skill_version < 1
       or char_length(coalesce(p_device_id, '')) not between 8 and 128
       or jsonb_typeof(coalesce(p_variables, '{}'::jsonb)) <> 'object'
       or p_mode not in ('TEST', 'EXECUTE') then
        raise exception 'Invalid Teach LJ run request';
    end if;

    if (p_mode = 'TEST' and p_status <> 'READY')
       or (p_mode = 'EXECUTE' and p_status not in ('RUNNING', 'WAITING_CONFIRMATION')) then
        raise exception 'Teach LJ run state does not match mode';
    end if;

    if p_status = 'WAITING_CONFIRMATION' then
        if jsonb_typeof(p_pending_confirmation) <> 'object'
           or p_confirmation_token_hash !~ '^[0-9a-f]{64}$'
           or p_confirmation_expires_at is null
           or p_confirmation_expires_at <= now() then
            raise exception 'Invalid initial Teach LJ confirmation';
        end if;
    elsif p_pending_confirmation is not null
       or p_confirmation_token_hash is not null
       or p_confirmation_expires_at is not null then
        raise exception 'Unexpected initial Teach LJ confirmation fields';
    end if;

    select * into skill_row
      from public.lj_skills
     where id = p_skill_id
       and user_id = p_user_id
       and deleted_at is null
     for update;
    if not found or skill_row.current_version <> p_skill_version then
        return;
    end if;
    if p_mode = 'EXECUTE' and not skill_row.enabled then
        return;
    end if;

    if not exists(
        select 1 from public.lj_skill_versions
         where skill_id = p_skill_id
           and user_id = p_user_id
           and version = p_skill_version
    ) then
        return;
    end if;

    return query
    insert into public.lj_skill_runs(
        skill_id, skill_version, user_id, device_id, mode, status,
        state_version, variables, current_step_index,
        pending_confirmation, confirmation_token_hash,
        confirmation_expires_at, created_at, updated_at
    ) values (
        p_skill_id, p_skill_version, p_user_id, p_device_id, p_mode, p_status,
        0, coalesce(p_variables, '{}'::jsonb), 0,
        p_pending_confirmation, p_confirmation_token_hash,
        p_confirmation_expires_at, now(), now()
    ) returning *;
end;
$$;

-- Compare-and-swap a runner-owned step. Only valid state transitions are
-- accepted, so a stale request cannot overwrite a cancellation or approval.
create or replace function public.transition_lj_skill_run(
    p_user_id uuid,
    p_run_id uuid,
    p_device_id text,
    p_expected_step integer,
    p_expected_state_version bigint,
    p_new_status text,
    p_new_step integer,
    p_pending_confirmation jsonb default null,
    p_confirmation_token_hash text default null,
    p_confirmation_expires_at timestamptz default null,
    p_error_message text default null,
    p_completed boolean default false
)
returns setof public.lj_skill_runs
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_run public.lj_skill_runs%rowtype;
    v_step_count integer;
begin
    select * into v_run
      from public.lj_skill_runs
     where id = p_run_id
       and user_id = p_user_id
       and device_id = p_device_id
       and current_step_index = p_expected_step
       and state_version = p_expected_state_version
       and (
         (mode = 'TEST' and status = 'READY')
         or (mode = 'EXECUTE' and status = 'RUNNING')
       )
     for update;
    if not found then
        return;
    end if;

    if p_new_status not in ('READY', 'RUNNING', 'WAITING_CONFIRMATION', 'SUCCEEDED', 'FAILED')
       or p_new_step not in (p_expected_step, p_expected_step + 1)
       or (p_new_status in ('READY', 'RUNNING') and p_completed)
       or (p_new_status = 'FAILED' and (p_new_step <> p_expected_step or not p_completed))
       or (p_new_status = 'SUCCEEDED' and (p_new_step <> p_expected_step + 1 or not p_completed)) then
        raise exception 'Invalid Teach LJ run transition';
    end if;

    if (v_run.mode = 'TEST' and p_new_status not in ('READY', 'SUCCEEDED', 'FAILED'))
       or (v_run.mode = 'EXECUTE' and p_new_status not in (
         'RUNNING', 'WAITING_CONFIRMATION', 'SUCCEEDED', 'FAILED'
       )) then
        raise exception 'Teach LJ transition state does not match run mode';
    end if;

    if p_new_status = 'WAITING_CONFIRMATION' then
        if jsonb_typeof(p_pending_confirmation) <> 'object'
           or p_confirmation_token_hash !~ '^[0-9a-f]{64}$'
           or p_confirmation_expires_at is null
           or p_confirmation_expires_at <= now()
           or p_completed then
            raise exception 'Invalid Teach LJ confirmation transition';
        end if;
    elsif p_pending_confirmation is not null
       or p_confirmation_token_hash is not null
       or p_confirmation_expires_at is not null then
        raise exception 'Unexpected Teach LJ confirmation fields';
    end if;

    if p_new_status = 'SUCCEEDED' then
        select jsonb_array_length(v.steps) into v_step_count
          from public.lj_skill_versions v
         where v.skill_id = v_run.skill_id
           and v.version = v_run.skill_version
           and v.user_id = v_run.user_id;
        if v_step_count is null or p_new_step <> v_step_count then
            raise exception 'Teach LJ run cannot finish before its final step';
        end if;
    end if;

    return query
    update public.lj_skill_runs r
       set status = p_new_status,
           state_version = r.state_version + 1,
           current_step_index = p_new_step,
           pending_confirmation = p_pending_confirmation,
           confirmation_token_hash = p_confirmation_token_hash,
           confirmation_expires_at = p_confirmation_expires_at,
           error_message = p_error_message,
           updated_at = now(),
           completed_at = case when p_completed then now() else null end
     where r.id = v_run.id
       and r.user_id = p_user_id
       and r.device_id = p_device_id
       and r.current_step_index = p_expected_step
       and r.state_version = p_expected_state_version
       and (
         (r.mode = 'TEST' and r.status = 'READY')
         or (r.mode = 'EXECUTE' and r.status = 'RUNNING')
       )
    returning r.*;
end;
$$;

-- Confirmation proof is compared, expiry-checked, and consumed in one locked
-- statement. The plaintext token never enters the database.
create or replace function public.confirm_lj_skill_run(
    p_user_id uuid,
    p_run_id uuid,
    p_device_id text,
    p_confirmation_token_hash text,
    p_expected_state_version bigint,
    p_approved boolean
)
returns setof public.lj_skill_runs
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
    if p_confirmation_token_hash !~ '^[0-9a-f]{64}$' then
        return;
    end if;
    return query
    update public.lj_skill_runs r
       set status = case when p_approved then 'RUNNING' else 'CANCELLED' end,
           state_version = r.state_version + 1,
           pending_confirmation = null,
           confirmation_token_hash = null,
           confirmation_expires_at = null,
           updated_at = now(),
           completed_at = case when p_approved then null else now() end
     where r.id = p_run_id
       and r.user_id = p_user_id
       and r.device_id = p_device_id
       and r.status = 'WAITING_CONFIRMATION'
       and r.mode = 'EXECUTE'
       and r.state_version = p_expected_state_version
       and r.confirmation_token_hash = p_confirmation_token_hash
       and r.confirmation_expires_at > now()
    returning r.*;
end;
$$;

create or replace function public.cancel_lj_skill_run(
    p_user_id uuid,
    p_run_id uuid,
    p_device_id text,
    p_expected_state_version bigint
)
returns setof public.lj_skill_runs
language sql
security definer
set search_path = public, pg_temp
as $$
    update public.lj_skill_runs r
       set status = 'CANCELLED',
           state_version = r.state_version + 1,
           pending_confirmation = null,
           confirmation_token_hash = null,
           confirmation_expires_at = null,
           updated_at = now(),
           completed_at = now()
     where r.id = p_run_id
       and r.user_id = p_user_id
       and r.device_id = p_device_id
       and r.state_version = p_expected_state_version
       and r.status in ('READY', 'WAITING_CONFIRMATION', 'RUNNING')
    returning r.*;
$$;

create or replace function public.cancel_lj_skill_runs_for_skill(
    p_user_id uuid,
    p_skill_id uuid
)
returns integer
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_count integer;
begin
    update public.lj_skill_runs
       set status = 'CANCELLED',
           state_version = state_version + 1,
           pending_confirmation = null,
           confirmation_token_hash = null,
           confirmation_expires_at = null,
           updated_at = now(),
           completed_at = now()
     where skill_id = p_skill_id
       and user_id = p_user_id
       and status in ('READY', 'WAITING_CONFIRMATION', 'RUNNING');
    get diagnostics v_count = row_count;
    return v_count;
end;
$$;

create or replace function public.delete_lj_skill(
    p_user_id uuid,
    p_skill_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    skill_row public.lj_skills%rowtype;
begin
    select * into skill_row
      from public.lj_skills
     where id = p_skill_id
       and user_id = p_user_id
       and deleted_at is null
     for update;
    if not found then
        return false;
    end if;

    update public.lj_skills
       set enabled = false, deleted_at = now(), updated_at = now()
     where id = p_skill_id and user_id = p_user_id;

    update public.lj_skill_runs
       set status = 'CANCELLED',
           state_version = state_version + 1,
           pending_confirmation = null,
           confirmation_token_hash = null,
           confirmation_expires_at = null,
           updated_at = now(),
           completed_at = now()
     where skill_id = p_skill_id
       and user_id = p_user_id
       and status in ('READY', 'WAITING_CONFIRMATION', 'RUNNING');
    return true;
end;
$$;

create or replace function public.reject_lj_skill_version_update()
returns trigger
language plpgsql
set search_path = public, pg_temp
as $$
begin
    raise exception 'Teach LJ Skill versions are immutable; create a new version instead';
end;
$$;

drop trigger if exists lj_skill_versions_immutable_update on public.lj_skill_versions;
create trigger lj_skill_versions_immutable_update
before update on public.lj_skill_versions
for each row execute function public.reject_lj_skill_version_update();

revoke all on function public.reject_lj_skill_version_update()
    from public, anon, authenticated, service_role;
revoke all on function public.valid_lj_skill_safety_policy(jsonb)
    from public, anon, authenticated, service_role;

alter table public.lj_skills enable row level security;
alter table public.lj_skill_versions enable row level security;
alter table public.lj_skill_runs enable row level security;
alter table public.lj_skill_run_events enable row level security;

revoke all on public.lj_skills from anon, authenticated;
revoke all on public.lj_skill_versions from anon, authenticated;
revoke all on public.lj_skill_runs from anon, authenticated;
revoke all on public.lj_skill_run_events from anon, authenticated;

revoke all on public.lj_skills from service_role;
revoke all on public.lj_skill_versions from service_role;
revoke all on public.lj_skill_runs from service_role;
revoke all on public.lj_skill_run_events from service_role;

grant select, update on public.lj_skills to service_role;
grant select on public.lj_skill_versions to service_role;
grant select on public.lj_skill_runs to service_role;
grant select, insert on public.lj_skill_run_events to service_role;

-- Revoke every installed overload first. This prevents an older draft RPC
-- signature from remaining callable after an additive migration rerun.
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
               'create_lj_skill',
               'create_lj_skill_version',
               'start_lj_skill_run',
               'transition_lj_skill_run',
               'confirm_lj_skill_run',
               'cancel_lj_skill_run',
               'cancel_lj_skill_runs_for_skill',
               'delete_lj_skill'
           ])
    loop
        execute format(
            'revoke all on function %s from public, anon, authenticated, service_role',
            function_row.signature
        );
    end loop;
end;
$$;

grant execute on function public.create_lj_skill(
    uuid, text, text, boolean, jsonb, jsonb, jsonb, jsonb, jsonb, text, text
) to service_role;
grant execute on function public.create_lj_skill_version(
    uuid, uuid, jsonb, jsonb, jsonb, jsonb, jsonb, text, text
) to service_role;
grant execute on function public.start_lj_skill_run(
    uuid, uuid, integer, text, text, text, jsonb, jsonb, text, timestamptz
) to service_role;
grant execute on function public.transition_lj_skill_run(
    uuid, uuid, text, integer, bigint, text, integer, jsonb, text, timestamptz, text, boolean
) to service_role;
grant execute on function public.confirm_lj_skill_run(
    uuid, uuid, text, text, bigint, boolean
) to service_role;
grant execute on function public.cancel_lj_skill_run(uuid, uuid, text, bigint)
    to service_role;
grant execute on function public.cancel_lj_skill_runs_for_skill(uuid, uuid)
    to service_role;
grant execute on function public.delete_lj_skill(uuid, uuid)
    to service_role;
grant execute on function public.valid_lj_skill_safety_policy(jsonb)
    to service_role;

commit;
