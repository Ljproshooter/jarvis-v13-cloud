-- V16.0.3: apply once before deploying the cloud update. Safe to rerun.
-- Builds on the completed V15.9.7 chat/memory migration; no old setup is rerun.
begin;

create table if not exists public.lj_coding_jobs (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users(id) on delete cascade,
    conversation_id text not null,
    request_id text not null,
    fingerprint text not null,
    prompt text not null check (char_length(prompt) between 1 and 8000),
    status text not null default 'QUEUED'
        check (status in ('QUEUED','RUNNING','PAUSED','STOPPING','STOPPED','COMPLETED')),
    progress text not null default 'Preparing your project',
    state jsonb not null default '{}'::jsonb,
    claim_token text not null,
    lease_token uuid,
    lease_until timestamptz,
    next_run_at timestamptz not null default now(),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (user_id, request_id),
    unique (id, user_id),
    foreign key (conversation_id, user_id)
        references public.lj_conversations(id, user_id) on delete cascade
);
create index if not exists lj_coding_queue_idx
    on public.lj_coding_jobs(next_run_at, created_at)
    where status in ('QUEUED','RUNNING','STOPPING');
create index if not exists lj_coding_conversation_idx
    on public.lj_coding_jobs(user_id, conversation_id, created_at desc);

-- Source archives are private, durable and cascade with the owning project.
-- No public URL, provider sandbox lifetime or Windows filesystem is trusted.
create table if not exists public.lj_coding_archives (
    job_id uuid primary key,
    user_id uuid not null,
    sha256 text not null check (sha256 ~ '^[0-9a-f]{64}$'),
    content_hash text not null,
    data_base64 text not null check (octet_length(data_base64) <= 44739244),
    manifest jsonb not null default '[]'::jsonb,
    saved_at timestamptz not null default now(),
    foreign key (job_id, user_id) references public.lj_coding_jobs(id, user_id) on delete cascade
);

create or replace function public.create_lj_coding_job(
    p_user_id uuid, p_conversation_id text, p_request_id text,
    p_fingerprint text, p_prompt text, p_options jsonb
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare j public.lj_coding_jobs%rowtype; allowance record; parent_job public.lj_coding_jobs%rowtype;
        source_archive public.lj_coding_archives%rowtype;
begin
    perform pg_advisory_xact_lock(hashtextextended(p_user_id::text, 160300));
    if not exists(select 1 from public.lj_conversations where id=p_conversation_id and user_id=p_user_id) then
        raise exception 'conversation not found';
    end if;
    select * into j from public.lj_coding_jobs where user_id=p_user_id and request_id=p_request_id;
    if found then
        if j.fingerprint <> p_fingerprint then
            return jsonb_build_object('conflict','This request ID was already used for different work.');
        end if;
        return to_jsonb(j);
    end if;
    if exists(select 1 from public.lj_coding_jobs where user_id=p_user_id
              and conversation_id=p_conversation_id and status in ('QUEUED','RUNNING','STOPPING')) then
        return jsonb_build_object('conflict','A coding job is already running in this chat. Open Coding Projects to view or stop it.');
    end if;
    if (select count(*) from public.lj_coding_jobs where user_id=p_user_id
        and status in ('QUEUED','RUNNING','STOPPING')) >= 3 then
        return jsonb_build_object('conflict','Three projects are already active. Stop or finish one before starting another.');
    end if;
    select * into allowance from public.reserve_lj_chat_usage(p_user_id,p_request_id,p_fingerprint,'DEVELOPER');
    if not coalesce(allowance.allowed,false) then
        return jsonb_build_object('denied',true,'reason',allowance.denial_reason);
    end if;
    select * into parent_job from public.lj_coding_jobs
      where user_id=p_user_id and conversation_id=p_conversation_id order by created_at desc limit 1;
    insert into public.lj_coding_jobs(user_id,conversation_id,request_id,fingerprint,prompt,claim_token,state)
    values(p_user_id,p_conversation_id,p_request_id,p_fingerprint,p_prompt,allowance.claim_token,
           jsonb_build_object('options',p_options,'parent_id',parent_job.id,'parent_prompt',parent_job.prompt,
             'parent_report',parent_job.state->'report','phase','BUILD','round',0))
    returning * into j;
    select * into source_archive from public.lj_coding_archives where job_id=parent_job.id and user_id=p_user_id;
    if found then
        insert into public.lj_coding_archives(job_id,user_id,sha256,content_hash,data_base64,manifest)
            values(j.id,p_user_id,source_archive.sha256,source_archive.content_hash,source_archive.data_base64,source_archive.manifest);
        update public.lj_coding_jobs set state=state || jsonb_build_object(
            'archive_sha256',source_archive.sha256,'content_hash',source_archive.content_hash,'manifest',source_archive.manifest)
            where id=j.id returning * into j;
    end if;
    return to_jsonb(j);
end $$;

create or replace function public.delete_lj_coding_job(p_job_id uuid,p_user_id uuid)
returns boolean language plpgsql security definer set search_path = public, pg_temp as $$
declare j public.lj_coding_jobs%rowtype;
begin
    perform pg_advisory_xact_lock(hashtextextended(p_user_id::text,160300));
    select * into j from public.lj_coding_jobs where id=p_job_id and user_id=p_user_id for update;
    if not found then return false; end if;
    if j.status in ('QUEUED','RUNNING','STOPPING') or j.state->>'response_id' is not null
       or coalesce((j.state->>'submitting')::boolean,false) then return false; end if;
    delete from public.lj_coding_jobs where id=j.id;
    return true;
end $$;

create or replace function public.resume_lj_coding_job(p_job_id uuid,p_user_id uuid)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare j public.lj_coding_jobs%rowtype; s jsonb;
begin
    perform pg_advisory_xact_lock(hashtextextended(p_user_id::text,160300));
    select * into j from public.lj_coding_jobs where id=p_job_id and user_id=p_user_id for update;
    if not found then return null; end if;
    if j.status not in ('PAUSED','STOPPED') then return to_jsonb(j); end if;
    if exists(select 1 from public.lj_coding_jobs where user_id=p_user_id and id<>p_job_id
        and conversation_id=j.conversation_id and status in ('QUEUED','RUNNING','STOPPING')) then
        return jsonb_build_object('conflict','Another job is active in this chat. Stop it before resuming this one.');
    end if;
    if (select count(*) from public.lj_coding_jobs where user_id=p_user_id
        and status in ('QUEUED','RUNNING','STOPPING'))>=3 then
        return jsonb_build_object('conflict','Three projects are already active. Stop or finish one first.');
    end if;
    s:=j.state;
    -- An uncertain POST could still be running. A new workspace prevents two
    -- responses changing the same files; restore only our durable checkpoint.
    if coalesce((s->>'submitting')::boolean,false) then
        s:=s || '{"container_id":null,"response_id":null,"previous_response_id":null,"restore_pending":false}'::jsonb;
    end if;
    update public.lj_coding_jobs set status='QUEUED',progress='Resuming your saved project',
        state=s || '{"submitting":false,"unchanged":0}'::jsonb,lease_token=null,lease_until=null,
        next_run_at=now(),updated_at=now() where id=j.id returning * into j;
    return to_jsonb(j);
end $$;

create or replace function public.save_lj_coding_checkpoint(
    p_job_id uuid,p_user_id uuid,p_lease uuid,p_status text,p_sha256 text,
    p_content_hash text,p_data text,p_manifest jsonb,p_state jsonb
) returns boolean language plpgsql security definer set search_path = public, pg_temp as $$
declare j public.lj_coding_jobs%rowtype;
begin
    select * into j from public.lj_coding_jobs where id=p_job_id and user_id=p_user_id for update;
    if not found or j.lease_token is distinct from p_lease or j.status<>p_status
       or j.status not in ('RUNNING','STOPPING') then return false; end if;
    insert into public.lj_coding_archives(job_id,user_id,sha256,content_hash,data_base64,manifest)
        values(j.id,j.user_id,p_sha256,p_content_hash,p_data,p_manifest)
        on conflict(job_id) do update set sha256=excluded.sha256,content_hash=excluded.content_hash,
          data_base64=excluded.data_base64,manifest=excluded.manifest,saved_at=now();
    update public.lj_coding_jobs set state=p_state,updated_at=now() where id=j.id;
    return true;
end $$;

create or replace function public.import_lj_coding_project(
    p_user_id uuid,p_conversation_id text,p_request_id text,p_sha256 text,
    p_content_hash text,p_data text,p_manifest jsonb
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare j public.lj_coding_jobs%rowtype;
begin
    perform pg_advisory_xact_lock(hashtextextended(p_user_id::text,160300));
    if not exists(select 1 from public.lj_conversations where id=p_conversation_id and user_id=p_user_id) then
        raise exception 'conversation not found';
    end if;
    select * into j from public.lj_coding_jobs where user_id=p_user_id and request_id=p_request_id;
    if found then
        if j.fingerprint<>p_sha256 or j.conversation_id<>p_conversation_id then
            return jsonb_build_object('conflict','This import ID was already used for different files.');
        end if;
        return to_jsonb(j);
    end if;
    if exists(select 1 from public.lj_coding_jobs where user_id=p_user_id and conversation_id=p_conversation_id
              and status in ('QUEUED','RUNNING','STOPPING')) then
        return jsonb_build_object('conflict','Stop the active job before replacing the source files in this chat.');
    end if;
    insert into public.lj_coding_jobs(user_id,conversation_id,request_id,fingerprint,prompt,status,progress,claim_token,state)
      values(p_user_id,p_conversation_id,p_request_id,p_sha256,'Imported project files','COMPLETED',
        'Source imported. Ask for changes in this chat.','',jsonb_build_object('phase','IMPORT',
        'archive_sha256',p_sha256,'content_hash',p_content_hash,'manifest',p_manifest,'round',0)) returning * into j;
    insert into public.lj_coding_archives(job_id,user_id,sha256,content_hash,data_base64,manifest)
      values(j.id,p_user_id,p_sha256,p_content_hash,p_data,p_manifest);
    return to_jsonb(j);
end $$;

-- A deleted active chat would orphan an in-flight model request. Require Stop
-- to complete first; all its files then cascade with the owner's conversation.
create or replace function public.guard_lj_coding_conversation_delete()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
begin
    if exists(select 1 from auth.users where id=old.user_id)
       and exists(select 1 from public.lj_coding_jobs where user_id=old.user_id and conversation_id=old.id
           and (status in ('QUEUED','RUNNING','STOPPING')
                or (status='PAUSED' and state->>'response_id' is not null))) then
        raise exception 'Stop the coding job in this conversation before deleting the chat.';
    end if;
    return old;
end $$;
drop trigger if exists lj_coding_guard_conversation_delete on public.lj_conversations;
create trigger lj_coding_guard_conversation_delete before delete on public.lj_conversations
for each row execute function public.guard_lj_coding_conversation_delete();

create or replace function public.claim_lj_coding_job(p_lease uuid)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare j public.lj_coding_jobs%rowtype;
begin
    select * into j from public.lj_coding_jobs
    where status in ('QUEUED','RUNNING','STOPPING') and next_run_at<=now()
      and (lease_until is null or lease_until<now())
    order by next_run_at,created_at for update skip locked limit 1;
    if not found then return null; end if;
    update public.lj_coding_jobs set lease_token=p_lease,lease_until=now()+interval '90 seconds',
      status=case when status='QUEUED' then 'RUNNING' else status end,updated_at=now()
      where id=j.id returning * into j;
    -- An active durable job must not be mistaken for an abandoned chat reservation.
    update public.lj_chat_usage_reservations set updated_at=now()
      where user_id=j.user_id and request_id=j.request_id and claim_token=j.claim_token and status='IN_PROGRESS';
    return to_jsonb(j);
end $$;

create or replace function public.finish_lj_coding_job(
    p_job_id uuid,p_user_id uuid,p_lease uuid,p_reply text,p_model text,p_state jsonb
) returns boolean language plpgsql security definer set search_path = public, pg_temp as $$
declare j public.lj_coding_jobs%rowtype;
begin
    select * into j from public.lj_coding_jobs where id=p_job_id and user_id=p_user_id for update;
    if not found or j.lease_token is distinct from p_lease or j.status<>'RUNNING' then return false; end if;
    if not exists(select 1 from public.lj_coding_archives where job_id=j.id and user_id=j.user_id
                  and sha256=p_state->>'archive_sha256') then
        raise exception 'completed code must have a saved project archive';
    end if;
    perform public.save_lj_chat_turn(j.user_id,j.conversation_id,j.request_id,j.claim_token,
        j.prompt,p_reply,p_model,null);
    update public.lj_coding_jobs set status='COMPLETED',progress='Project saved',
      state=p_state || jsonb_build_object('reply',p_reply,'model',p_model),
      lease_token=null,lease_until=null,updated_at=now() where id=j.id;
    return true;
end $$;

alter table public.lj_memories add column if not exists memory_key text;
alter table public.lj_memories add column if not exists source_kind text not null default 'MANUAL';
create unique index if not exists lj_memory_key_idx on public.lj_memories(user_id,memory_key)
    where memory_key is not null;
create table if not exists public.lj_memory_events (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users(id) on delete cascade,
    conversation_id text,
    request_id text not null,
    message text not null check (char_length(message)<=24000),
    status text not null default 'QUEUED' check (status in ('QUEUED','DONE')),
    lease_until timestamptz,
    generation bigint not null default 0,
    created_at timestamptz not null default now(),
    unique(user_id,request_id),
    foreign key (conversation_id,user_id) references public.lj_conversations(id,user_id) on delete cascade
);
create table if not exists public.lj_memory_control (
    user_id uuid primary key references auth.users(id) on delete cascade,
    generation bigint not null default 0
);
create index if not exists lj_memory_event_queue_idx on public.lj_memory_events(created_at)
    where status='QUEUED';

-- Invalidate in-flight learning on forget/edit/pause, including older clients.
create or replace function public.invalidate_lj_memory_learning()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
declare owner_id uuid;
begin
    if current_setting('lj.automatic_memory_write',true)='yes' then
        return coalesce(new,old);
    end if;
    owner_id := coalesce(new.user_id,old.user_id);
    if not exists(select 1 from auth.users where id=owner_id) then return coalesce(new,old); end if;
    insert into public.lj_memory_control(user_id,generation) values(owner_id,1)
      on conflict(user_id) do update set generation=public.lj_memory_control.generation+1;
    return coalesce(new,old);
end $$;
drop trigger if exists lj_memory_invalidate_learning on public.lj_memories;
create trigger lj_memory_invalidate_learning after update or delete on public.lj_memories
for each row execute function public.invalidate_lj_memory_learning();

create or replace function public.invalidate_lj_memory_preferences()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
begin
    if (old.values->'memory_enabled') is distinct from (new.values->'memory_enabled')
       or (old.values->'automatic_memory_enabled') is distinct from (new.values->'automatic_memory_enabled') then
        insert into public.lj_memory_control(user_id,generation) values(new.user_id,1)
          on conflict(user_id) do update set generation=public.lj_memory_control.generation+1;
    end if;
    return new;
end $$;
drop trigger if exists lj_memory_preferences_changed on public.lj_user_preferences;
create trigger lj_memory_preferences_changed after update on public.lj_user_preferences
for each row execute function public.invalidate_lj_memory_preferences();

create or replace function public.enqueue_lj_memory_event(
    p_user_id uuid,p_conversation_id text,p_request_id text,p_message text
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare prefs jsonb; g bigint; e public.lj_memory_events%rowtype;
begin
    perform pg_advisory_xact_lock(hashtextextended(p_user_id::text,160301));
    select values into prefs from public.lj_user_preferences where user_id=p_user_id;
    if coalesce(prefs->>'memory_enabled','true')='false'
       or coalesce(prefs->>'automatic_memory_enabled','true')='false' then return null; end if;
    insert into public.lj_memory_control(user_id) values(p_user_id) on conflict do nothing;
    select generation into g from public.lj_memory_control where user_id=p_user_id for update;
    insert into public.lj_memory_events(user_id,conversation_id,request_id,message,generation)
      values(p_user_id,p_conversation_id,p_request_id,left(p_message,24000),g)
      on conflict(user_id,request_id) do nothing returning * into e;
    if e.id is null then select * into e from public.lj_memory_events
        where user_id=p_user_id and request_id=p_request_id; end if;
    return to_jsonb(e);
end $$;

create or replace function public.apply_lj_memory_event(p_event_id uuid,p_user_id uuid,p_facts jsonb)
returns integer language plpgsql security definer set search_path = public, pg_temp as $$
declare e public.lj_memory_events%rowtype; prefs jsonb; g bigint; f jsonb;
        n integer:=0; existing public.lj_memories%rowtype;
begin
    perform pg_advisory_xact_lock(hashtextextended(p_user_id::text,160301));
    select * into e from public.lj_memory_events where id=p_event_id and user_id=p_user_id for update;
    if not found or e.status='DONE' then return 0; end if;
    select generation into g from public.lj_memory_control where user_id=p_user_id for update;
    select values into prefs from public.lj_user_preferences where user_id=p_user_id;
    update public.lj_memory_events set status='DONE',message='',lease_until=null where id=e.id;
    if g is distinct from e.generation or coalesce(prefs->>'memory_enabled','true')='false'
       or coalesce(prefs->>'automatic_memory_enabled','true')='false' then return 0; end if;
    perform set_config('lj.automatic_memory_write','yes',true);
    for f in select value from jsonb_array_elements(p_facts) limit 8 loop
        if length(f->>'fact') not between 1 and 500 or length(f->>'key') not between 1 and 120
           or length(f->>'evidence')<3 or position(lower(f->>'evidence') in lower(e.message))=0 then continue; end if;
        select * into existing from public.lj_memories where user_id=p_user_id and memory_key=f->>'key';
        if found and (not existing.enabled or existing.updated_at>e.created_at) then continue; end if;
        if not found and (select count(*) from public.lj_memories where user_id=p_user_id)>=200 then continue; end if;
        if exists(select 1 from public.lj_memories where user_id=p_user_id and normalized_fact=f->>'normalized'
                  and memory_key is distinct from f->>'key') then continue; end if;
        if existing.id is not null then
            update public.lj_memories set fact=f->>'fact',normalized_fact=f->>'normalized',
                updated_at=e.created_at,source_kind='AUTOMATIC',source_conversation_id=e.conversation_id where id=existing.id;
        else
          insert into public.lj_memories(user_id,fact,normalized_fact,category,source_conversation_id,
            memory_key,source_kind,updated_at)
        values(p_user_id,f->>'fact',f->>'normalized',f->>'category',e.conversation_id,
            f->>'key','AUTOMATIC',e.created_at);
        end if;
        n:=n+1;
    end loop;
    return n;
end $$;

create or replace function public.forget_lj_memory(
    p_user_id uuid,p_all boolean default false,p_memory_id uuid default null,p_key text default null,
    p_normalized text default null
) returns integer language plpgsql security definer set search_path = public, pg_temp as $$
declare n integer;
begin
    perform pg_advisory_xact_lock(hashtextextended(p_user_id::text,160301));
    -- Fence queued work even when there are no saved rows to delete yet.
    insert into public.lj_memory_control(user_id,generation) values(p_user_id,1)
      on conflict(user_id) do update set generation=public.lj_memory_control.generation+1;
    perform set_config('lj.automatic_memory_write','yes',true);
    delete from public.lj_memories where user_id=p_user_id and
        (p_all or id=p_memory_id or memory_key=p_key or normalized_fact=p_normalized);
    get diagnostics n=row_count;
    update public.lj_memory_events set status='DONE',message='',lease_until=null
      where user_id=p_user_id and status='QUEUED';
    return n;
end $$;

create or replace function public.edit_lj_memory(p_user_id uuid,p_memory_id uuid,p_changes jsonb)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare m public.lj_memories%rowtype;
begin
    -- Match the learner's lock order before locking the memory row.
    perform pg_advisory_xact_lock(hashtextextended(p_user_id::text,160301));
    update public.lj_memories set
        fact=coalesce(p_changes->>'fact',fact),
        normalized_fact=coalesce(p_changes->>'normalized_fact',normalized_fact),
        category=coalesce(p_changes->>'category',category),
        enabled=coalesce((p_changes->>'enabled')::boolean,enabled),
        source_kind=case when p_changes ? 'fact' then 'MANUAL' else source_kind end,
        updated_at=now()
      where id=p_memory_id and user_id=p_user_id returning * into m;
    return case when m.id is null then null else to_jsonb(m) end;
end $$;

create or replace function public.delete_lj_conversation(p_user_id uuid,p_conversation_id text)
returns boolean language plpgsql security definer set search_path = public, pg_temp as $$
declare removed integer;
begin
    perform pg_advisory_xact_lock(hashtextextended(p_user_id::text,160300));
    perform pg_advisory_xact_lock(hashtextextended(p_user_id::text,160301));
    if exists(select 1 from public.lj_coding_jobs where user_id=p_user_id and conversation_id=p_conversation_id
        and (status in ('QUEUED','RUNNING','STOPPING')
             or (status='PAUSED' and state->>'response_id' is not null))) then return false; end if;
    delete from public.lj_conversations where id=p_conversation_id and user_id=p_user_id;
    get diagnostics removed=row_count;
    return removed=1;
end $$;

create or replace function public.set_lj_automatic_memory_enabled(p_user_id uuid,p_enabled boolean)
returns boolean language plpgsql security definer set search_path = public, pg_temp as $$
begin
    perform pg_advisory_xact_lock(hashtextextended(p_user_id::text,160301));
    insert into public.lj_user_preferences as prefs(user_id,values,revision,updated_at)
      values(p_user_id,jsonb_build_object('automatic_memory_enabled',p_enabled),1,now())
      on conflict(user_id) do update set values=coalesce(prefs.values,'{}'::jsonb)
        || jsonb_build_object('automatic_memory_enabled',p_enabled),revision=prefs.revision+1,updated_at=now();
    return p_enabled;
end $$;

create or replace function public.claim_lj_memory_event()
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare e public.lj_memory_events%rowtype;
begin
    select * into e from public.lj_memory_events where status='QUEUED'
      and (lease_until is null or lease_until<now()) order by created_at for update skip locked limit 1;
    if not found then return null; end if;
    update public.lj_memory_events set lease_until=now()+interval '100 seconds' where id=e.id;
    return to_jsonb(e);
end $$;

do $$ declare t text; begin
    foreach t in array array['lj_coding_jobs','lj_coding_archives','lj_memory_events','lj_memory_control'] loop
        execute format('alter table public.%I enable row level security',t);
        execute format('revoke all on table public.%I from public,anon,authenticated',t);
        execute format('grant select,insert,update,delete on table public.%I to service_role',t);
    end loop;
end $$;
revoke all on function public.create_lj_coding_job(uuid,text,text,text,text,jsonb) from public,anon,authenticated;
revoke all on function public.claim_lj_coding_job(uuid) from public,anon,authenticated;
revoke all on function public.finish_lj_coding_job(uuid,uuid,uuid,text,text,jsonb) from public,anon,authenticated;
revoke all on function public.enqueue_lj_memory_event(uuid,text,text,text) from public,anon,authenticated;
revoke all on function public.apply_lj_memory_event(uuid,uuid,jsonb) from public,anon,authenticated;
grant execute on function public.create_lj_coding_job(uuid,text,text,text,text,jsonb) to service_role;
grant execute on function public.claim_lj_coding_job(uuid) to service_role;
grant execute on function public.finish_lj_coding_job(uuid,uuid,uuid,text,text,jsonb) to service_role;
grant execute on function public.enqueue_lj_memory_event(uuid,text,text,text) to service_role;
grant execute on function public.apply_lj_memory_event(uuid,uuid,jsonb) to service_role;
revoke all on function public.set_lj_automatic_memory_enabled(uuid,boolean) from public,anon,authenticated;
revoke all on function public.claim_lj_memory_event() from public,anon,authenticated;
grant execute on function public.set_lj_automatic_memory_enabled(uuid,boolean) to service_role;
grant execute on function public.claim_lj_memory_event() to service_role;
revoke all on function public.resume_lj_coding_job(uuid,uuid) from public,anon,authenticated;
revoke all on function public.save_lj_coding_checkpoint(uuid,uuid,uuid,text,text,text,text,jsonb,jsonb) from public,anon,authenticated;
revoke all on function public.import_lj_coding_project(uuid,text,text,text,text,text,jsonb) from public,anon,authenticated;
revoke all on function public.forget_lj_memory(uuid,boolean,uuid,text,text) from public,anon,authenticated;
grant execute on function public.resume_lj_coding_job(uuid,uuid) to service_role;
grant execute on function public.save_lj_coding_checkpoint(uuid,uuid,uuid,text,text,text,text,jsonb,jsonb) to service_role;
grant execute on function public.import_lj_coding_project(uuid,text,text,text,text,text,jsonb) to service_role;
grant execute on function public.forget_lj_memory(uuid,boolean,uuid,text,text) to service_role;
revoke all on function public.delete_lj_coding_job(uuid,uuid) from public,anon,authenticated;
grant execute on function public.delete_lj_coding_job(uuid,uuid) to service_role;
revoke all on function public.edit_lj_memory(uuid,uuid,jsonb) from public,anon,authenticated;
revoke all on function public.delete_lj_conversation(uuid,text) from public,anon,authenticated;
grant execute on function public.edit_lj_memory(uuid,uuid,jsonb) to service_role;
grant execute on function public.delete_lj_conversation(uuid,text) to service_role;
commit;
