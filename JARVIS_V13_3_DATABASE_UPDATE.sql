-- LJ AI V13.3 database update
-- Run this once in Supabase -> SQL Editor after the earlier V13 setup.
-- It is safe to run again. It does not delete accounts, tickets or chat logs.

begin;

update public.plan_catalog
set daily_message_limit = case plan_key
    when 'FREE' then 15
    when 'PREMIUM' then 100
    when 'PREMIUM_PLUS' then 250
    when 'VIP' then 1000
    when 'ADMIN' then null
    else daily_message_limit
end
where plan_key in ('FREE', 'PREMIUM', 'PREMIUM_PLUS', 'VIP', 'ADMIN');

commit;

select plan_key, daily_message_limit
from public.plan_catalog
where plan_key in ('FREE', 'PREMIUM', 'PREMIUM_PLUS', 'VIP', 'ADMIN')
order by sort_order;
