-- Apply after LJ_AI_TEACH_LJ_DATABASE_UPDATE.sql. Idempotent and non-destructive.
-- Run permissions belong to the run, never to user variables or stored labels.
begin;
alter table public.lj_skill_runs
    add column if not exists control_mode text not null default 'SAFE_MODE';
do $$
begin
    if not exists (
        select 1 from pg_constraint
         where conrelid = 'public.lj_skill_runs'::regclass
           and conname = 'lj_skill_runs_control_mode_check'
    ) then
        alter table public.lj_skill_runs add constraint lj_skill_runs_control_mode_check
            check (control_mode in ('SAFE_MODE', 'FULL_ACCESS'));
    end if;
end;
$$;

create or replace function public.start_lj_skill_run_v1601(
    p_user_id uuid, p_skill_id uuid, p_skill_version integer, p_device_id text,
    p_mode text, p_status text, p_variables jsonb, p_control_mode text,
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
    run_row public.lj_skill_runs%rowtype;
begin
    if p_control_mode is null or p_control_mode not in ('SAFE_MODE', 'FULL_ACCESS') then
        raise exception 'Invalid Teach LJ control mode';
    end if;
    -- Reuse the existing owner/version/device checks and Skill row lock. The
    -- insert and permission binding both commit or roll back together.
    select * into run_row from public.start_lj_skill_run(
        p_user_id, p_skill_id, p_skill_version, p_device_id, p_mode, p_status,
        p_variables, p_pending_confirmation, p_confirmation_token_hash,
        p_confirmation_expires_at
    );
    if not found then
        return;
    end if;
    return query
    update public.lj_skill_runs as runs
       set control_mode = case when p_mode = 'EXECUTE' then p_control_mode else 'SAFE_MODE' end
     where runs.id = run_row.id
       and runs.user_id = p_user_id
       and runs.device_id = p_device_id
    returning runs.*;
end;
$$;
revoke all on function public.start_lj_skill_run_v1601(
    uuid,uuid,integer,text,text,text,jsonb,text,jsonb,text,timestamptz
) from public, anon, authenticated;
grant execute on function public.start_lj_skill_run_v1601(
    uuid,uuid,integer,text,text,text,jsonb,text,jsonb,text,timestamptz
) to service_role;
commit;
notify pgrst, 'reload schema';
