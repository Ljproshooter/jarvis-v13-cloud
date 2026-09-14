-- LJ AI V15.9.6 Smart Mode and atomic text-usage update.
-- Run once in Supabase SQL Editor after LJ_AI_V15_9_MAJOR_UPDATE.sql.
begin;

alter table public.lj_usage_cycles
    add column if not exists max_reasoning_limit integer;
alter table public.lj_usage_cycles
    add column if not exists max_reasoning_used integer not null default 0;

create or replace function public.ensure_lj_usage_cycle(p_user_id uuid)
returns public.lj_usage_cycles
language plpgsql
security definer
set search_path=public
as $$
declare
    s public.lj_subscriptions%rowtype;
    r text;
    p text := 'FREE';
    b text := 'DAILY';
    cs timestamptz;
    ce timestamptz;
    tl int := 25;
    il int := 3;
    vl int := 0;
    ml int := 0;
    rf int := 0;
    rq boolean := false;
    c public.lj_usage_cycles%rowtype;
begin
    select upper(coalesce(role,'USER')) into r from public.profiles where id=p_user_id;
    if r='ADMIN' then
        p:='ADMIN'; b:='YEARLY'; cs:=date_trunc('year',now()); ce:=cs+interval '1 year';
        tl:=null; il:=null; vl:=null; ml:=null;
    else
        select * into s from public.lj_subscriptions
        where user_id=p_user_id and status in('active','trialing')
          and coalesce(current_period_end,now()+interval '1 day')>now();
        if found then
            p:=s.plan_key; b:=s.billing_period; cs:=coalesce(s.current_period_start,now());
            ce:=coalesce(s.current_period_end,now()+case b when '3_MONTHS' then interval '3 months' when 'YEARLY' then interval '1 year' else interval '1 month' end);
            if p='BASIC' then
                tl:=case b when '3_MONTHS' then 4500 when 'YEARLY' then 18250 else 1500 end;
                il:=case b when '3_MONTHS' then 180 when 'YEARLY' then 730 else 60 end;
                vl:=case b when '3_MONTHS' then 16200 when 'YEARLY' then 74100 else 5400 end;
                rf:=case when b='YEARLY' then 1 else 0 end;
            elsif p='PREMIUM' then
                tl:=case b when '3_MONTHS' then 9000 when 'YEARLY' then 36500 else 3000 end;
                il:=case b when '3_MONTHS' then 450 when 'YEARLY' then 1825 else 150 end;
                vl:=case b when '3_MONTHS' then 108000 when 'YEARLY' then 219000 else 18000 end;
                rf:=case when b='YEARLY' then 2 else 0 end;
            elsif p='VIP' then
                tl:=case b when '3_MONTHS' then 9000 when 'YEARLY' then 36500 else 3000 end;
                il:=case b when '3_MONTHS' then 900 when 'YEARLY' then 3650 else 300 end;
                vl:=case b when '3_MONTHS' then 108000 when 'YEARLY' then 438000 else 36000 end;
                ml:=case b when '3_MONTHS' then 300 when 'YEARLY' then 1200 else 100 end;
                rf:=case when b='YEARLY' then 5 else 0 end;
                rq:=b='3_MONTHS';
            end if;
        else
            cs:=date_trunc('day',now()); ce:=cs+interval '1 day';
        end if;
    end if;

    select * into c from public.lj_usage_cycles
    where user_id=p_user_id and plan_key=p and billing_period=b
      and cycle_start<=now() and cycle_end>now()
    order by cycle_end desc limit 1 for update;
    if not found then
        insert into public.lj_usage_cycles(
            user_id,plan_key,billing_period,cycle_start,cycle_end,text_limit,image_limit,
            voice_seconds_limit,max_reasoning_limit,refills_total,refill_on_request
        ) values(p_user_id,p,b,cs,ce,tl,il,vl,ml,rf,rq)
        on conflict(user_id,cycle_start) do update set
            plan_key=excluded.plan_key,billing_period=excluded.billing_period,
            cycle_end=excluded.cycle_end,text_limit=excluded.text_limit,
            image_limit=excluded.image_limit,voice_seconds_limit=excluded.voice_seconds_limit,
            max_reasoning_limit=excluded.max_reasoning_limit,refills_total=excluded.refills_total,
            refill_on_request=excluded.refill_on_request,updated_at=now()
        returning * into c;
    else
        update public.lj_usage_cycles set
            max_reasoning_limit=ml,
            max_reasoning_used=least(max_reasoning_used,coalesce(ml,max_reasoning_used)),
            updated_at=now()
        where user_id=p_user_id and cycle_start=c.cycle_start
        returning * into c;
    end if;
    return c;
end
$$;

create or replace function public.consume_lj_chat_usage(
    p_user_id uuid,
    p_mode text default 'NORMAL'
)
returns table(
    allowed boolean,
    denial_reason text,
    plan_key text,
    text_remaining integer,
    max_reasoning_remaining integer
)
language plpgsql
security definer
set search_path=public
as $$
declare
    c public.lj_usage_cycles%rowtype;
    m text := upper(coalesce(p_mode,'NORMAL'));
    use_max boolean;
begin
    c:=public.ensure_lj_usage_cycle(p_user_id);
    use_max:=m='DEVELOPER';
    if c.text_limit is not null and c.text_used+1>c.text_limit then
        allowed:=false; denial_reason:='TEXT_LIMIT';
    elsif use_max and c.plan_key not in ('VIP','ADMIN') then
        allowed:=false; denial_reason:='MODE_NOT_INCLUDED';
    elsif use_max and c.max_reasoning_limit is not null
          and c.max_reasoning_used+1>c.max_reasoning_limit then
        allowed:=false; denial_reason:='MAX_REASONING_LIMIT';
    else
        update public.lj_usage_cycles set
            text_used=text_used+1,
            max_reasoning_used=max_reasoning_used+case when use_max then 1 else 0 end,
            updated_at=now()
        where user_id=p_user_id and cycle_start=c.cycle_start
        returning * into c;
        allowed:=true; denial_reason:='';
    end if;
    plan_key:=c.plan_key;
    text_remaining:=case when c.text_limit is null then null else greatest(0,c.text_limit-c.text_used) end;
    max_reasoning_remaining:=case when c.max_reasoning_limit is null then null else greatest(0,c.max_reasoning_limit-c.max_reasoning_used) end;
    return next;
end
$$;

revoke all on function public.consume_lj_chat_usage(uuid,text) from public,anon,authenticated;
grant execute on function public.consume_lj_chat_usage(uuid,text) to service_role;

commit;
