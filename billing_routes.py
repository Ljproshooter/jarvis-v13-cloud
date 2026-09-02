"""Stripe-hosted billing for LJ AI V15.9. Permanent Stripe secrets stay on Render."""
from __future__ import annotations
import hashlib, hmac, json, os, time
from datetime import datetime, timezone
from typing import Any, Callable
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, field_validator

PLAN_CATALOG: dict[str, dict[str, Any]] = {
 "FREE":{"name":"Free","periods":{"MONTHLY":0.0},"text":25,"images":3,"voice_seconds":0,"refills":0},
 "BASIC":{"name":"Basic","periods":{"MONTHLY":15.0,"3_MONTHS":45.0,"YEARLY":171.0},"text":{"MONTHLY":1500,"3_MONTHS":4500,"YEARLY":18250},"images":{"MONTHLY":60,"3_MONTHS":180,"YEARLY":730},"voice_seconds":{"MONTHLY":5400,"3_MONTHS":16200,"YEARLY":74100},"refills":{"MONTHLY":0,"3_MONTHS":0,"YEARLY":1}},
 "PREMIUM":{"name":"Premium","periods":{"MONTHLY":24.99,"3_MONTHS":74.97,"YEARLY":284.89},"text":{"MONTHLY":3000,"3_MONTHS":9000,"YEARLY":36500},"images":{"MONTHLY":150,"3_MONTHS":450,"YEARLY":1825},"voice_seconds":{"MONTHLY":18000,"3_MONTHS":108000,"YEARLY":219000},"refills":{"MONTHLY":0,"3_MONTHS":0,"YEARLY":2}},
 "VIP":{"name":"VIP","periods":{"MONTHLY":59.99,"3_MONTHS":179.97,"YEARLY":683.89},"text":{"MONTHLY":3000,"3_MONTHS":9000,"YEARLY":36500},"images":{"MONTHLY":300,"3_MONTHS":900,"YEARLY":3650},"voice_seconds":{"MONTHLY":36000,"3_MONTHS":108000,"YEARLY":438000},"refills":{"MONTHLY":0,"3_MONTHS":0,"YEARLY":5},"three_month_refills_on_request":True},
}
PRICE_ENV={(p,t):f"STRIPE_PRICE_{p}_{t}" for p in ("BASIC","PREMIUM","VIP") for t in ("MONTHLY","3_MONTHS","YEARLY")}
ACTIVE={"active","trialing"}

def public_plan_catalog()->list[dict[str,Any]]:
 out=[]
 for key,value in PLAN_CATALOG.items():
  periods=value["periods"]; text=value["text"]
  out.append({"plan_key":key,"display_name":value["name"],"monthly_price_usd":float(periods.get("MONTHLY",0)),"daily_message_limit":text if isinstance(text,int) else int(text.get("MONTHLY",0)),"ai_voice_enabled":key!="FREE","cedar_voice_enabled":key!="FREE","checkout_url":"","billing_periods_usd":periods,"text_allowance":value["text"],"image_allowance":value["images"],"voice_seconds":value["voice_seconds"],"refills":value["refills"],"refill_on_request":bool(value.get("three_month_refills_on_request")),"screen_monitoring":True,"local_currency_at_checkout":True})
 return out

class CheckoutRequest(BaseModel):
 plan:str=Field(min_length=3,max_length=20); period:str=Field(min_length=3,max_length=20)
 @field_validator("plan","period")
 @classmethod
 def upper(cls,v:str)->str:return v.strip().upper()

def _v(i:Any,k:str,d:Any="")->Any:return i.get(k,d) if isinstance(i,dict) else getattr(i,k,d)
def _norm(v:str)->str:return {"PREMIUM_PLUS":"PREMIUM","1_MONTH":"MONTHLY","12_MONTHS":"YEARLY"}.get(v.strip().upper().replace("-","_").replace(" ","_"),v.strip().upper())

async def _stripe(method:str,path:str,data:Any=None)->dict[str,Any]:
 secret=os.getenv("STRIPE_SECRET_KEY","").strip()
 if not secret: raise HTTPException(503,"Stripe billing has not been configured yet.")
 try:
  async with httpx.AsyncClient(timeout=30) as client:r=await client.request(method,f"https://api.stripe.com/v1/{path}",auth=(secret,""),data=data)
 except httpx.RequestError as exc: raise HTTPException(503,"Stripe is temporarily unreachable.") from exc
 try: payload=r.json()
 except ValueError: payload={}
 if r.status_code>=400: raise HTTPException(502,str((payload.get("error") or {}).get("message") or "Stripe rejected the request.")[:500])
 return payload

def _signed(raw:bytes,header:str)->bool:
 secret=os.getenv("STRIPE_WEBHOOK_SECRET","").strip(); parts={}
 for item in header.split(","):
  k,_,v=item.partition("="); parts.setdefault(k.strip(),[]).append(v.strip())
 try: stamp=int((parts.get("t") or [""])[0])
 except ValueError:return False
 if not secret or abs(int(time.time())-stamp)>300:return False
 digest=hmac.new(secret.encode(),str(stamp).encode()+b"."+raw,hashlib.sha256).hexdigest()
 return any(hmac.compare_digest(digest,x) for x in parts.get("v1",[]))

def create_billing_router(*,current_identity:Callable[...,Any],rest_request:Callable[...,Any],insert_audit:Callable[...,Any])->APIRouter:
 r=APIRouter(tags=["billing"])
 @r.get("/v1/billing/catalog")
 async def catalog():return {"currency":"USD","local_currency_at_checkout":True,"plans":[{"plan":k,**v,"screen_monitoring":True,"annual_discount_percent":5 if k!="FREE" else 0} for k,v in PLAN_CATALOG.items()]}
 @r.get("/v1/billing/subscription")
 async def subscription(identity:Any=Depends(current_identity)):
  rows=await rest_request("GET","lj_subscriptions",params={"user_id":f"eq.{_v(identity,'user_id')}","select":"*","limit":"1"}) or []
  return rows[0] if rows else {"status":"free","plan_key":"FREE"}
 @r.post("/v1/billing/checkout")
 async def checkout(body:CheckoutRequest,identity:Any=Depends(current_identity)):
  if str(_v(identity,"role","USER")).upper()=="ADMIN":raise HTTPException(403,"Administrator accounts already have full access and cannot buy a plan.")
  plan,period=_norm(body.plan),_norm(body.period); env=PRICE_ENV.get((plan,period)); price=os.getenv(env or "","").strip()
  if not env or not price:raise HTTPException(503,"That Stripe price is not configured yet.")
  uid,email=str(_v(identity,"user_id")),str(_v(identity,"email"))
  form={"mode":"subscription","line_items[0][price]":price,"line_items[0][quantity]":"1","client_reference_id":uid,"customer_email":email,"success_url":os.getenv("STRIPE_SUCCESS_URL","https://lj-ai-mobile-staging.onrender.com/v1/billing/success?session_id={CHECKOUT_SESSION_ID}"),"cancel_url":os.getenv("STRIPE_CANCEL_URL","https://lj-ai-mobile-staging.onrender.com/v1/billing/cancel"),"allow_promotion_codes":"true","adaptive_pricing[enabled]":"true","metadata[user_id]":uid,"metadata[plan]":plan,"metadata[period]":period,"subscription_data[metadata][user_id]":uid,"subscription_data[metadata][plan]":plan,"subscription_data[metadata][period]":period}
  out=await _stripe("POST","checkout/sessions",form); await insert_audit(uid,"BILLING_CHECKOUT_CREATED",{"plan":plan,"period":period})
  return {"checkout_url":str(out.get("url") or ""),"session_id":str(out.get("id") or "")}
 @r.post("/v1/billing/portal")
 async def portal(identity:Any=Depends(current_identity)):
  rows=await rest_request("GET","lj_subscriptions",params={"user_id":f"eq.{_v(identity,'user_id')}","select":"stripe_customer_id","limit":"1"}) or []; customer=str(rows[0].get("stripe_customer_id") or "") if rows else ""
  if not customer:raise HTTPException(404,"No Stripe subscription is linked to this account yet.")
  out=await _stripe("POST","billing_portal/sessions",{"customer":customer,"return_url":os.getenv("STRIPE_PORTAL_RETURN_URL","https://lj-ai-mobile-staging.onrender.com/v1/billing/success")}); return {"portal_url":str(out.get("url") or "")}
 @r.post("/v1/billing/webhook")
 async def webhook(req:Request):
  raw=await req.body()
  if not _signed(raw,req.headers.get("stripe-signature","")):raise HTTPException(400,"Invalid Stripe webhook signature.")
  event=json.loads(raw); eid=str(event.get("id") or "")
  if not eid:raise HTTPException(400,"Stripe webhook event ID is missing.")
  existing=await rest_request("GET","billing_webhook_events",params={"event_id":f"eq.{eid}","select":"event_id","limit":"1"}) or []
  if existing:return {"received":True}
  obj=((event.get("data") or {}).get("object") or {}); meta=obj.get("metadata") or {}; uid=str(meta.get("user_id") or obj.get("client_reference_id") or ""); plan=_norm(str(meta.get("plan") or "")); period=_norm(str(meta.get("period") or "")); status=str(obj.get("status") or ""); subscription_id=str(obj.get("subscription") or obj.get("id") or "")
  linked=[]
  if subscription_id:
   linked=await rest_request("GET","lj_subscriptions",params={"stripe_subscription_id":f"eq.{subscription_id}","select":"user_id,plan_key,billing_period,stripe_customer_id,current_period_start,current_period_end","limit":"1"}) or []
  previous=linked[0] if linked else {}
  uid=uid or str(previous.get("user_id") or "")
  plan=plan if plan in {"BASIC","PREMIUM","VIP"} else _norm(str(previous.get("plan_key") or ""))
  period=period if period in {"MONTHLY","3_MONTHS","YEARLY"} else _norm(str(previous.get("billing_period") or ""))
  if event.get("type")=="checkout.session.completed":status="active" if str(obj.get("payment_status")) in {"paid","no_payment_required"} else "incomplete"
  if uid and plan in {"BASIC","PREMIUM","VIP"} and period in {"MONTHLY","3_MONTHS","YEARLY"}:
   stamp=datetime.now(timezone.utc); start=obj.get("current_period_start"); end=obj.get("current_period_end"); start_iso=datetime.fromtimestamp(int(start),tz=timezone.utc).isoformat() if start else str(previous.get("current_period_start") or stamp.isoformat()); end_iso=datetime.fromtimestamp(int(end),tz=timezone.utc).isoformat() if end else str(previous.get("current_period_end") or "") or None; active=status in ACTIVE
   row={"user_id":uid,"plan_key":plan if active else "FREE","billing_period":period,"status":status or str(event.get("type")),"stripe_customer_id":str(obj.get("customer") or previous.get("stripe_customer_id") or ""),"stripe_subscription_id":subscription_id,"current_period_start":start_iso,"updated_at":stamp.isoformat()}
   if end_iso:row["current_period_end"]=end_iso
   await rest_request("POST","lj_subscriptions",payload=row,prefer="resolution=merge-duplicates,return=minimal")
   profile_patch={"plan":plan if active else "FREE"}
   if end_iso:profile_patch["plan_expires_at"]=end_iso
   await rest_request("PATCH","profiles",params={"id":f"eq.{uid}"},payload=profile_patch,prefer="return=minimal")
  await rest_request("POST","billing_webhook_events",payload={"event_id":eid,"event_type":str(event.get("type")),"processed_at":datetime.now(timezone.utc).isoformat()},prefer="return=minimal"); return {"received":True}
 @r.get("/v1/billing/success",response_class=HTMLResponse)
 async def success():return HTMLResponse("<body style='background:#03101f;color:#58dcff;font:18px sans-serif;padding:48px'><h1>Payment complete</h1><p>Return to LJ AI. Your plan refreshes automatically on Windows and Android.</p></body>")
 @r.get("/v1/billing/cancel",response_class=HTMLResponse)
 async def cancel():return HTMLResponse("<body style='background:#03101f;color:white;font:18px sans-serif;padding:48px'><h1>Checkout cancelled</h1><p>No payment was made.</p></body>")
 return r
