"""Staged authenticated image-creation endpoint for LJ AI Mobile."""

from __future__ import annotations

from typing import Any, Awaitable, Callable

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator


class ImageGenerationRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=2000)

    @field_validator("prompt")
    @classmethod
    def clean_prompt(cls, value: str) -> str:
        clean = value.strip()
        if not clean:
            raise ValueError("Describe the image you want LJ AI to create.")
        return clean


def create_image_generation_router(
    *,
    current_identity: Callable[..., Awaitable[Any]],
    limiter: Any,
    consume_image_allowance: Callable[[Any], Awaitable[dict[str, Any]]],
    openai_json: Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]],
    record_api_usage: Callable[..., Awaitable[None]],
    save_chat_log: Callable[..., Awaitable[None]],
    image_model: str,
    image_plans: set[str],
) -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["mobile-images"])

    @router.post("/images/generate")
    async def generate_image(
        body: ImageGenerationRequest,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        if identity.effective_plan not in image_plans:
            raise HTTPException(
                status_code=403,
                detail="Image creation is unavailable for this account.",
            )
        await limiter.enforce(f"image-generate:{identity.user_id}", 6, 60)
        allowance = await consume_image_allowance(identity)
        payload: dict[str, Any] = {
            "model": image_model,
            "instructions": (
                "Create one polished original image that follows the user's request. "
                "Do not claim the image was photographed or edited from a source when none was supplied."
            ),
            "input": [{
                "role": "user",
                "content": [{"type": "input_text", "text": body.prompt}],
            }],
            "tools": [{"type": "image_generation"}],
            "tool_choice": {"type": "image_generation"},
        }
        data = await openai_json("responses", payload)
        image_call = next(
            (
                item for item in data.get("output") or []
                if isinstance(item, dict)
                and item.get("type") == "image_generation_call"
                and isinstance(item.get("result"), str)
            ),
            None,
        )
        if image_call is None:
            raise HTTPException(status_code=502, detail="The image creator returned no image.")
        image_base64 = str(image_call.get("result") or "")
        if not image_base64 or len(image_base64) > 42_000_000:
            raise HTTPException(status_code=502, detail="The created image was too large to return safely.")
        usage = data.get("usage") or {}
        input_tokens = int(usage.get("input_tokens") or 0)
        output_tokens = int(usage.get("output_tokens") or 0)
        await record_api_usage(
            identity.user_id,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )
        await save_chat_log(
            identity,
            f"[Image generation] {body.prompt}",
            "[Image created and returned to the user's phone]",
            image_model,
            input_tokens,
            output_tokens,
            False,
        )
        return {
            "image_base64": image_base64,
            "media_type": "image/png",
            "revised_prompt": str(image_call.get("revised_prompt") or "")[:2000],
            "model": image_model,
            "messages_used": allowance.get("text_used"),
            "daily_limit": allowance.get("text_limit"),
            "allowance": allowance,
        }

    return router
