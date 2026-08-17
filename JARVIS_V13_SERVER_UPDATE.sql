-- JARVIS V13 server update
-- Run this entire file once in Supabase -> SQL Editor after the main setup.
-- It corrects V12.3 plan limits and adds server-side usage/login/chat logging.

begin;

update public.plan_catalog
set daily_message_limit = case plan_key
    when 'FREE' then 5
    when 'PREMIUM' then 100
    when 'PREMIUM_PLUS' then 250
    when 'VIP' then 1000
    when 'ADMIN' then null
    else daily_message_limit
end
where plan_key in ('FREE', 'PREMIUM', 'PREMIUM_PLUS', 'VIP', 'ADMIN');

alter table public.profiles
    add column if not exists last_seen_at timestamptz,
    add column if not exists last_login_at timestamptz,
    add column if not exists login_count bigint not null default 0;

create index if not exists profiles_last_seen_idx
    on public.profiles (last_seen_at desc);

create table if not exists public.chat_logs (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users(id) on delete cascade,
    prompt text not null,
    reply text not null,
    model text not null,
    input_tokens bigint not null default 0,
    output_tokens bigint not null default 0,
    from_voice boolean not null default false,
    created_at timestamptz not null default now(),
    constraint chat_logs_prompt_length check (char_length(prompt) between 1 and 8000),
    constraint chat_logs_reply_length check (char_length(reply) between 1 and 20000),
    constraint chat_logs_tokens_nonnegative check (input_tokens >= 0 and output_tokens >= 0)
);

create index if not exists chat_logs_user_created_idx
    on public.chat_logs (user_id, created_at desc);
create index if not exists chat_logs_created_idx
    on public.chat_logs (created_at desc);

alter table public.chat_logs enable row level security;

drop policy if exists chat_logs_read_own_or_admin on public.chat_logs;
create policy chat_logs_read_own_or_admin
on public.chat_logs for select
to authenticated
using ((select auth.uid()) = user_id or public.is_jarvis_admin());

revoke all on public.chat_logs from anon, authenticated;
grant select on public.chat_logs to authenticated;
grant all on public.chat_logs to service_role;

create or replace function public.record_jarvis_login(p_user_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
    update public.profiles
    set last_login_at = now(),
        last_seen_at = now(),
        login_count = login_count + 1,
        updated_at = now()
    where id = p_user_id;
end;
$$;

create or replace function public.record_jarvis_api_usage(
    p_user_id uuid,
    p_input_tokens bigint default 0,
    p_output_tokens bigint default 0,
    p_transcription_seconds numeric default 0,
    p_speech_characters bigint default 0
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
    if p_input_tokens < 0
       or p_output_tokens < 0
       or p_transcription_seconds < 0
       or p_speech_characters < 0 then
        raise exception 'Usage values cannot be negative';
    end if;

    insert into public.daily_usage (
        user_id,
        usage_date,
        input_tokens,
        output_tokens,
        transcription_seconds,
        speech_characters,
        updated_at
    )
    values (
        p_user_id,
        current_date,
        p_input_tokens,
        p_output_tokens,
        p_transcription_seconds,
        p_speech_characters,
        now()
    )
    on conflict (user_id, usage_date)
    do update set
        input_tokens = public.daily_usage.input_tokens + excluded.input_tokens,
        output_tokens = public.daily_usage.output_tokens + excluded.output_tokens,
        transcription_seconds = public.daily_usage.transcription_seconds + excluded.transcription_seconds,
        speech_characters = public.daily_usage.speech_characters + excluded.speech_characters,
        updated_at = now();
end;
$$;

revoke all on function public.record_jarvis_login(uuid) from public, anon, authenticated;
revoke all on function public.record_jarvis_api_usage(uuid, bigint, bigint, numeric, bigint)
    from public, anon, authenticated;

grant execute on function public.record_jarvis_login(uuid) to service_role;
grant execute on function public.record_jarvis_api_usage(uuid, bigint, bigint, numeric, bigint)
    to service_role;

commit;

select 'JARVIS V13 server database update complete' as status;

