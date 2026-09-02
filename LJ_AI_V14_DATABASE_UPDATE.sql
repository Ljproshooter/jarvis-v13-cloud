-- LJ AI V14 cloud update
-- Run once in Supabase -> SQL Editor after the earlier V13/V13.3 setup.
-- Safe to run again. This does not delete accounts, tickets, broadcasts or chat logs.

begin;

create table if not exists public.password_recovery_requests (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users(id) on delete cascade,
    username text not null,
    email text not null,
    status text not null default 'OPEN'
        check (status in ('OPEN', 'APPROVED', 'DENIED', 'COMPLETED', 'EXPIRED')),
    secret_hash text not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    expires_at timestamptz not null default (now() + interval '48 hours'),
    approved_by uuid references auth.users(id) on delete set null,
    approved_at timestamptz,
    completed_at timestamptz
);

create table if not exists public.password_recovery_messages (
    id bigint generated always as identity primary key,
    request_id uuid not null references public.password_recovery_requests(id) on delete cascade,
    sender text not null check (sender in ('USER', 'ADMIN')),
    message text not null check (char_length(message) between 1 and 1500),
    created_at timestamptz not null default now()
);

create index if not exists password_recovery_requests_user_idx
    on public.password_recovery_requests(user_id, updated_at desc);
create index if not exists password_recovery_requests_status_idx
    on public.password_recovery_requests(status, updated_at desc);
create index if not exists password_recovery_messages_request_idx
    on public.password_recovery_messages(request_id, created_at asc);

alter table public.password_recovery_requests enable row level security;
alter table public.password_recovery_messages enable row level security;

revoke all on public.password_recovery_requests from anon, authenticated;
revoke all on public.password_recovery_messages from anon, authenticated;
grant all on public.password_recovery_requests to service_role;
grant all on public.password_recovery_messages to service_role;
grant usage, select on sequence public.password_recovery_messages_id_seq to service_role;

commit;

select status, count(*) as requests
from public.password_recovery_requests
group by status
order by status;
