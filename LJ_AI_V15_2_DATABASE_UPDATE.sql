-- LJ AI V15.2 public community update
-- Run once in Supabase -> SQL Editor before deploying the V15.2 cloud files.
-- Safe to run again. It does not delete accounts, tickets, news or chat logs.

begin;

create table if not exists public.community_messages (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users(id) on delete cascade,
    username text not null check (char_length(username) between 3 and 24),
    message text not null check (char_length(message) between 1 and 500),
    created_at timestamptz not null default now()
);

create index if not exists community_messages_created_idx
    on public.community_messages(created_at desc);
create index if not exists community_messages_user_idx
    on public.community_messages(user_id, created_at desc);

alter table public.community_messages enable row level security;

-- Public app users communicate through the LJ AI Cloud API. They never receive
-- direct database write access or the Supabase service-role credential.
revoke all on public.community_messages from anon, authenticated;
grant all on public.community_messages to service_role;

commit;

select count(*) as community_messages_ready
from public.community_messages;
