"""Cross-device preferences, conversations and leased voice handover for V15.9."""
from __future__ import annotations
import hashlib,secrets
from datetime import datetime,timedelta,timezone
from typing import Any,Callable,Literal
from fastapi import APIRouter,Depends,Header,HTTPException
from pydantic import BaseModel,Field

SAFE={"theme","voice_speed","voice_output","allow_interruptions","auto_voice_handover","sync_preferences","sign_in_briefing","screen_monitoring","mouse_control","messaging_access","file_access","weather_location","personality"}
def uid(i):return str(i.get("user_id") if isinstance(i,dict) else i.user_id)
def did(i):return str(i.get("device_id") if isinstance(i,dict) else i.device_id)
def now():return datetime.now(timezone.utc)
def hashed(v):return hashlib.sha256(v.encode()).hexdigest()
class Pref(BaseModel):values:dict[str,Any]=Field(default_factory=dict);base_revision:int=Field(0,ge=0)
class Conv(BaseModel):conversation_id:str|None=Field(None,max_length=80);title:str=Field("New conversation",max_length=120)
class Msg(BaseModel):role:Literal["user","assistant"];content:str=Field(min_length=1,max_length=20000);message_id:str|None=None;images:list[str]=Field(default_factory=list,max_length=6)
class VStart(BaseModel):platform:Literal["WINDOWS","ANDROID"];conversation_id:str|None=None;transcript_tail:list[dict[str,Any]]=Field(default_factory=list,max_length=20);auto_handover:bool=False
class Claim(BaseModel):platform:Literal["WINDOWS","ANDROID"]
class Offer(BaseModel):target_platform:Literal["WINDOWS","ANDROID"]
class Beat(BaseModel):transcript_tail:list[dict[str,Any]]=Field(default_factory=list,max_length=20);state:Literal["LISTENING","SPEAKING","IDLE"]="IDLE"

def create_sync_router(
 *,
 current_identity:Callable[...,Any],
 rest_request:Callable[...,Any],
 insert_audit:Callable[...,Any],
 consume_voice_usage:Callable[...,Any],
)->APIRouter:
 r=APIRouter(tags=["sync"])
 @r.get("/v1/sync/preferences")
 async def getprefs(identity=Depends(current_identity)):
  rows=await rest_request("GET","lj_user_preferences",params={"user_id":f"eq.{uid(identity)}","select":"values,revision,updated_at","limit":"1"}) or [];return rows[0] if rows else {"values":{},"revision":0}
 @r.put("/v1/sync/preferences")
 async def putprefs(body:Pref,identity=Depends(current_identity)):
  rows=await rest_request("GET","lj_user_preferences",params={"user_id":f"eq.{uid(identity)}","select":"values,revision","limit":"1"}) or [];old=rows[0] if rows else {"values":{},"revision":0};rev=int(old.get("revision") or 0)
  if rows and body.base_revision!=rev:raise HTTPException(409,detail={"message":"Preferences changed on another device.",**old})
  clean={k:(v[:200] if isinstance(v,str) else v) for k,v in body.values.items() if k in SAFE and isinstance(v,(str,bool,int,float))};row={"user_id":uid(identity),"values":{**(old.get("values") or {}),**clean},"revision":rev+1,"updated_at":now().isoformat()};await rest_request("POST","lj_user_preferences",payload=row,prefer="resolution=merge-duplicates,return=minimal");return row
 @r.get("/v1/sync/conversations")
 async def conversations(limit:int=30,identity=Depends(current_identity)):return await rest_request("GET","lj_conversations",params={"user_id":f"eq.{uid(identity)}","select":"*","order":"updated_at.desc","limit":str(max(1,min(100,limit)))}) or []
 @r.post("/v1/sync/conversations")
 async def newconv(body:Conv,identity=Depends(current_identity)):
  row={"id":body.conversation_id or secrets.token_urlsafe(24),"user_id":uid(identity),"title":body.title.strip() or "New conversation","created_at":now().isoformat(),"updated_at":now().isoformat()};await rest_request("POST","lj_conversations",payload=row,prefer="resolution=merge-duplicates,return=minimal");return row
 async def owned(cid,identity):
  rows=await rest_request("GET","lj_conversations",params={"id":f"eq.{cid}","user_id":f"eq.{uid(identity)}","select":"id","limit":"1"}) or []
  if not rows:raise HTTPException(404,"Conversation not found.")
 @r.get("/v1/sync/conversations/{cid}/messages")
 async def messages(cid:str,limit:int=100,identity=Depends(current_identity)):
  await owned(cid,identity);return await rest_request("GET","lj_conversation_messages",params={"conversation_id":f"eq.{cid}","select":"*","order":"created_at.asc","limit":str(max(1,min(200,limit)))}) or []
 @r.post("/v1/sync/conversations/{cid}/messages")
 async def addmsg(cid:str,body:Msg,identity=Depends(current_identity)):
  await owned(cid,identity);row={"id":body.message_id or secrets.token_urlsafe(20),"conversation_id":cid,"user_id":uid(identity),"role":body.role,"content":body.content,"images":body.images,"source_device_id":did(identity),"created_at":now().isoformat()};await rest_request("POST","lj_conversation_messages",payload=row,prefer="resolution=merge-duplicates,return=minimal");await rest_request("PATCH","lj_conversations",params={"id":f"eq.{cid}"},payload={"updated_at":now().isoformat()},prefer="return=minimal");return row
 async def voice(sid,identity):
  rows=await rest_request("GET","lj_voice_sessions",params={"id":f"eq.{sid}","user_id":f"eq.{uid(identity)}","select":"*","limit":"1"}) or []
  if not rows:raise HTTPException(404,"Voice session not found.")
  return rows[0]
 def lease(row,token,identity):
  if not token or not secrets.compare_digest(str(row.get("lease_token_hash") or ""),hashed(token)) or str(row.get("active_device_id"))!=did(identity):raise HTTPException(409,"This device no longer owns the voice session.")
 async def meter_since(row,identity):
  raw=str(row.get("updated_at") or row.get("created_at") or "").strip()
  try:
   stamp=datetime.fromisoformat(raw.replace("Z","+00:00"));stamp=stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)
  except (TypeError,ValueError):
   stamp=now()
  seconds=max(0,min(60,int((now()-stamp).total_seconds())))
  if seconds<=0:return {"voice_seconds_remaining":None}
  return await consume_voice_usage(identity,seconds)
 @r.post("/v1/sync/voice/start")
 async def start(body:VStart,identity=Depends(current_identity)):
  active_rows=await rest_request("GET","lj_voice_sessions",params={"user_id":f"eq.{uid(identity)}","status":"in.(ACTIVE,HANDOVER_REQUESTED)","select":"*","order":"updated_at.desc","limit":"4"}) or []
  inherited_tail=body.transcript_tail
  for old in active_rows:
   other_device=str(old.get("active_device_id") or "")!=did(identity)
   if other_device and not (body.auto_handover or bool(old.get("auto_handover"))):
    raise HTTPException(409,"Voice is active on another linked device. Offer or claim a handover first.")
   try:await meter_since(old,identity)
   finally:
    await rest_request("PATCH","lj_voice_sessions",params={"id":f"eq.{old.get('id')}"},payload={"status":"ENDED","lease_expires_at":now().isoformat(),"updated_at":now().isoformat()},prefer="return=minimal")
   if other_device and not inherited_tail:inherited_tail=list(old.get("transcript_tail") or [])[-20:]
  token=secrets.token_urlsafe(40);row={"id":secrets.token_urlsafe(28),"user_id":uid(identity),"conversation_id":body.conversation_id,"active_device_id":did(identity),"active_platform":body.platform,"status":"ACTIVE","auto_handover":body.auto_handover,"transcript_tail":inherited_tail,"lease_token_hash":hashed(token),"lease_expires_at":(now()+timedelta(seconds=45)).isoformat(),"created_at":now().isoformat(),"updated_at":now().isoformat()};await rest_request("POST","lj_voice_sessions",payload=row,prefer="return=minimal");return {**row,"lease_token":token}
 @r.get("/v1/sync/voice/active")
 async def active(identity=Depends(current_identity)):
  rows=await rest_request("GET","lj_voice_sessions",params={"user_id":f"eq.{uid(identity)}","status":"in.(ACTIVE,HANDOVER_REQUESTED)","select":"id,active_device_id,active_platform,status,handover_target,auto_handover,transcript_tail,updated_at","order":"updated_at.desc","limit":"1"}) or [];return rows[0] if rows else {"status":"NONE"}
 @r.post("/v1/sync/voice/{sid}/handover")
 async def offer(sid:str,body:Offer,x_lj_voice_lease:str=Header(default=""),identity=Depends(current_identity)):
  row=await voice(sid,identity);lease(row,x_lj_voice_lease,identity);usage=await meter_since(row,identity);await rest_request("PATCH","lj_voice_sessions",params={"id":f"eq.{sid}"},payload={"status":"HANDOVER_REQUESTED","handover_target":body.target_platform,"updated_at":now().isoformat()},prefer="return=minimal");return {"status":"HANDOVER_REQUESTED","voice_seconds_remaining":usage.get("voice_seconds_remaining")}
 @r.post("/v1/sync/voice/{sid}/claim")
 async def claim(sid:str,body:Claim,identity=Depends(current_identity)):
  row=await voice(sid,identity)
  if row.get("status")!="HANDOVER_REQUESTED" and not row.get("auto_handover"):raise HTTPException(409,"The active device has not offered a handover.")
  token=secrets.token_urlsafe(40);patch={"active_device_id":did(identity),"active_platform":body.platform,"status":"ACTIVE","handover_target":None,"lease_token_hash":hashed(token),"lease_expires_at":(now()+timedelta(seconds=45)).isoformat(),"updated_at":now().isoformat()};await rest_request("PATCH","lj_voice_sessions",params={"id":f"eq.{sid}"},payload=patch,prefer="return=minimal");return {**patch,"id":sid,"lease_token":token,"transcript_tail":row.get("transcript_tail") or []}
 @r.post("/v1/sync/voice/{sid}/heartbeat")
 async def beat(sid:str,body:Beat,x_lj_voice_lease:str=Header(default=""),identity=Depends(current_identity)):
  row=await voice(sid,identity);lease(row,x_lj_voice_lease,identity);usage=await meter_since(row,identity);remaining=usage.get("voice_seconds_remaining");exhausted=remaining is not None and int(remaining)<=0;expires=(now()+timedelta(seconds=45)).isoformat();await rest_request("PATCH","lj_voice_sessions",params={"id":f"eq.{sid}"},payload={"transcript_tail":body.transcript_tail,"last_voice_state":body.state,"lease_expires_at":expires,"updated_at":now().isoformat(),"status":"ENDED" if exhausted else "ACTIVE"},prefer="return=minimal");return {"status":"ENDED" if exhausted else "ACTIVE","lease_expires_at":expires,"voice_seconds_remaining":remaining,"allowance_exhausted":exhausted}
 @r.post("/v1/sync/voice/{sid}/end")
 async def end(sid:str,x_lj_voice_lease:str=Header(default=""),identity=Depends(current_identity)):
  row=await voice(sid,identity);lease(row,x_lj_voice_lease,identity)
  try:await meter_since(row,identity)
  except HTTPException as error:
   if error.status_code!=429:raise
  await rest_request("PATCH","lj_voice_sessions",params={"id":f"eq.{sid}"},payload={"status":"ENDED","lease_expires_at":now().isoformat(),"updated_at":now().isoformat()},prefer="return=minimal");return {"ended":True}
 return r
