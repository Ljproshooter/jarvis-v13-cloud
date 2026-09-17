// Runs the real migration and existing reservation/chat-save functions in
// PostgreSQL via PGlite. Install @electric-sql/pglite as a test-only dependency.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
const { PGlite } = await import(process.env.LJ_PGLITE_MODULE || "@electric-sql/pglite");
const db = new PGlite();
const owner = "00000000-0000-4000-8000-000000000001";
const other = "00000000-0000-4000-8000-000000000002";
const lease = "00000000-0000-4000-8000-000000000010";
const hash = "a".repeat(64);
const scalar = async (sql, args=[]) => Object.values((await db.query(sql, args)).rows[0])[0];
const rpc = async (name, args) => scalar(
  "select public." + name + "(" + args.map((_, i) => "$" + (i + 1)).join(",") + ")", args);
const original = await readFile(new URL("../LJ_AI_V15_9_7_CHAT_MEMORY_UPDATE.sql", import.meta.url), "utf8");
const migration = await readFile(new URL("../LJ_AI_V16_0_3_CODING_MEMORY_UPDATE.sql", import.meta.url), "utf8");
function section(start, end) {
  return original.slice(original.indexOf(start), original.indexOf(end, original.indexOf(start)));
}
await db.exec(`
  create role anon; create role authenticated; create role service_role bypassrls;
  create schema auth;
  create table auth.users(id uuid primary key);
  create table public.lj_conversations(
    id text primary key, user_id uuid not null references auth.users on delete cascade,
    title text not null default 'New chat', updated_at timestamptz default now(),
    last_message_preview text, message_count integer default 0, unique(id,user_id));
  create table public.lj_conversation_messages(
    id text primary key, conversation_id text not null, user_id uuid not null, role text not null,
    content text not null, images jsonb, source_device_id text, request_id text, model text,
    metadata jsonb, created_at timestamptz default now(),
    foreign key(conversation_id,user_id) references lj_conversations(id,user_id) on delete cascade,
    unique(conversation_id,user_id,request_id,role));
  create table public.lj_user_preferences(
    user_id uuid primary key references auth.users on delete cascade, values jsonb default '{}',
    revision integer default 1,updated_at timestamptz default now());
  create table public.lj_usage_cycles(
    user_id uuid references auth.users on delete cascade, cycle_start timestamptz default '2026-09-01',
    plan_key text default 'VIP',text_limit integer default 100,text_used integer default 0,
    max_reasoning_limit integer default 100,max_reasoning_used integer default 0,
    updated_at timestamptz default now(),primary key(user_id,cycle_start));
  create function public.ensure_lj_usage_cycle(p_user_id uuid)
  returns public.lj_usage_cycles language plpgsql as $$
  declare c public.lj_usage_cycles%rowtype;
  begin
    insert into public.lj_usage_cycles(user_id) values(p_user_id) on conflict do nothing;
    select * into c from public.lj_usage_cycles where user_id=p_user_id for update;
    return c;
  end $$;
`);
await db.exec(section("create table if not exists public.lj_memories", "create or replace function public.set_lj_memory_enabled"));
await db.exec(section("create table if not exists public.lj_chat_usage_reservations", "alter table public.lj_chat_usage_reservations"));
await db.exec(section("create or replace function public.reserve_lj_chat_usage(", "drop function if exists public.complete_lj_chat_usage"));
await db.exec(section("create or replace function public.save_lj_chat_turn(", "create or replace function public.delete_lj_conversation"));
await db.exec(migration);
await db.exec(migration); // A repeated deployment must preserve existing schema.
await db.query("insert into auth.users(id) values($1),($2)", [owner,other]);
await db.query("insert into lj_conversations(id,user_id) values('project-chat-1',$1),('project-chat-2',$2)", [owner,other]);
let count = 0;
const check = (value, expected) => { assert.deepEqual(value,expected); count++; };
const createArgs = [owner,"project-chat-1","coding-request-1",hash,"Build a game",{}];
let job = await rpc("create_lj_coding_job", createArgs);
check(job.status,"QUEUED");
check((await rpc("create_lj_coding_job", createArgs)).id,job.id);
check(await scalar("select max_reasoning_used from lj_usage_cycles where user_id=$1",[owner]),1);
check(Boolean((await rpc("create_lj_coding_job",[...createArgs.slice(0,3),"b".repeat(64),"different",{}])).conflict),true);
await assert.rejects(rpc("create_lj_coding_job",[other,"project-chat-1","foreign-request",hash,"Steal files",{}]));
count++;
job = await rpc("claim_lj_coding_job",[lease]);
check(job.status,"RUNNING");
check(await rpc("claim_lj_coding_job",["00000000-0000-4000-8000-000000000011"]),null);
await assert.rejects(db.query("delete from lj_conversations where id='project-chat-1'"));
count++;
check(await rpc("save_lj_coding_checkpoint",[job.id,other,lease,"RUNNING",hash,hash,"eA==",[],{}]),false);
const state = {archive_sha256:hash,phase:"REVIEW",round:2};
check(await rpc("save_lj_coding_checkpoint",[job.id,owner,lease,"RUNNING",hash,hash,"eA==",[],state]),true);
check(await rpc("finish_lj_coding_job",[job.id,owner,lease,"Ready","gpt-6-astra",state]),true);
check(await scalar("select count(*)::int from lj_conversation_messages"),2);
check(await scalar("select status from lj_chat_usage_reservations where request_id='coding-request-1'"),"COMPLETED");
check(await rpc("finish_lj_coding_job",[job.id,owner,lease,"Again","gpt-6-astra",state]),false);
const next = await rpc("create_lj_coding_job",[owner,"project-chat-1","coding-request-2",hash,"Add a menu",{}]);
check(next.state.parent_id,job.id);
check(next.state.parent_prompt,"Build a game");
check(await scalar("select sha256 from lj_coding_archives where job_id=$1",[next.id]),hash);
check(await rpc("delete_lj_coding_job",[next.id,owner]),false);
await db.query("update lj_coding_jobs set status='PAUSED' where id=$1",[next.id]);
const active = await rpc("create_lj_coding_job",[owner,"project-chat-1","coding-request-3",hash,"Another change",{}]);
check(Boolean((await rpc("resume_lj_coding_job",[next.id,owner])).conflict),true);
await db.query("update lj_coding_jobs set status='STOPPED' where id=$1",[active.id]);
check((await rpc("resume_lj_coding_job",[next.id,owner])).status,"QUEUED");
check(await scalar("select max_reasoning_used from lj_usage_cycles where user_id=$1",[owner]),3);
await db.query("update lj_coding_jobs set status='STOPPED' where id=$1",[next.id]);
const imported = await rpc("import_lj_coding_project",[owner,"project-chat-1","import-request-1",hash,hash,"eA==",[]]);
check(imported.state.phase,"IMPORT");
check((await rpc("import_lj_coding_project",[owner,"project-chat-1","import-request-1",hash,hash,"eA==",[]])).id,imported.id);
check(await scalar("select max_reasoning_used from lj_usage_cycles where user_id=$1",[owner]),3);

let turn = 0;
const enqueue = (message) => rpc("enqueue_lj_memory_event",[owner,"project-chat-1","memory-event-"+(++turn),message]);
const facts = (color) => [{key:"preference.favorite_color",fact:"My favourite colour is "+color,
  normalized:"my favourite colour is "+color,category:"PREFERENCE",evidence:"My favourite colour is "+color}];
const apply = (event,color) => rpc("apply_lj_memory_event",[event.id,owner,facts(color)]);
let event = await enqueue("My favourite colour is purple");
check(await apply(event,"purple"),1);
check(await apply(event,"purple"),0);
check(await scalar("select message from lj_memory_events where id=$1",[event.id]),"");
const stale = await enqueue("My favourite colour is blue");
const newer = await enqueue("My favourite colour is green");
check(await apply(newer,"green"),1);
check(await apply(stale,"blue"),0);
check(await scalar("select fact from lj_memories where user_id=$1",[owner]),"My favourite colour is green");
event = await enqueue("My favourite colour is purple");
check(await rpc("forget_lj_memory",[owner,false,null,"preference.favorite_color",null]),1);
check(await apply(event,"purple"),0);
check(await scalar("select count(*)::int from lj_memories"),0);
event = await enqueue("My favourite colour is purple");
check(await rpc("forget_lj_memory",[owner,true,null,null,null]),0);
check(await apply(event,"purple"),0); // Empty Clear All must still fence queued work.
event = await enqueue("My favourite colour is purple");
check(await rpc("set_lj_automatic_memory_enabled",[owner,false]),false);
check(await apply(event,"purple"),0);
check(await enqueue("My favourite colour is blue"),null);
await rpc("set_lj_automatic_memory_enabled",[owner,true]);
event = await enqueue("My favourite colour is purple");
check(await rpc("apply_lj_memory_event",[event.id,other,facts("purple")]),0);
check(await apply(event,"purple"),1);
event = await enqueue("My favourite colour is blue");
await db.query("update lj_memories set enabled=false where user_id=$1",[owner]);
check(await apply(event,"blue"),0);
await db.query("update lj_memories set enabled=true where user_id=$1",[owner]);
const memoryId=await scalar("select id from lj_memories where user_id=$1",[owner]);
event=await enqueue("My favourite colour is blue");
const edited=await rpc("edit_lj_memory",[owner,memoryId,{fact:"My favourite colour is green",normalized_fact:"my favourite colour is green"}]);
check(edited.source_kind,"MANUAL");
check(await apply(event,"blue"),0);
await db.query("update lj_memories set source_kind='AUTOMATIC' where id=$1",[memoryId]);
await db.query(`insert into lj_memories(user_id,fact,normalized_fact)
  select $1,'Fact '||i,'fact '||i from generate_series(1,199) i`,[owner]);
event = await enqueue("My favourite colour is blue");
check(await apply(event,"blue"),1); // Corrections work at the 200-memory cap.
check(await scalar("select count(*)::int from lj_memories"),200);
check(await scalar("select has_table_privilege('authenticated','public.lj_coding_archives','SELECT')"),false);
check(await scalar("select has_function_privilege('authenticated','public.forget_lj_memory(uuid,boolean,uuid,text,text)','EXECUTE')"),false);
check(await rpc("delete_lj_conversation",[other,"project-chat-1"]),false);
check(await rpc("delete_lj_conversation",[owner,"project-chat-1"]),true);
check(await scalar("select count(*)::int from lj_coding_archives"),0);
check(await scalar("select count(*)::int from lj_memories"),200); // Memory survives chat deletion.
await db.query("delete from auth.users where id=$1",[owner]);
check(await scalar("select count(*)::int from lj_memories"),0);
console.log(count + " PostgreSQL migration/state/owner/memory assertions passed");
await db.close();
