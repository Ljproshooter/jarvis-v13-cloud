-- LJ AI V15.4 voice, community and news reliability update
-- Run once in Supabase -> SQL Editor before deploying the V15.4 cloud files.
-- Safe to run again. It does not delete accounts, tickets, news, community posts or chat logs.

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
revoke all on public.community_messages from anon, authenticated;
grant all on public.community_messages to service_role;

-- News receipts already cascade when an administrator deletes a broadcast.
-- Reassert the server-only grants needed by the new Clear All News endpoint.
grant all on public.broadcasts to service_role;
grant all on public.broadcast_receipts to service_role;

commit;

select
    (select count(*) from public.community_messages) as community_messages_ready,
    (select count(*) from public.broadcasts) as published_news_ready;
