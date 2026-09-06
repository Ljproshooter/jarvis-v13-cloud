"""Authenticated image creation and mobile image editing for LJ AI.

The Android client exchanges JSON rather than multipart bodies, so source and
result images are carried as validated base64. Keep the validation here as a
second line of defence even though the Android client also validates locally.
"""

from __future__ import annotations

import base64
from typing import Any, Awaitable, Callable, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator


MAX_SOURCE_IMAGE_BYTES = 8 * 1024 * 1024
MAX_RESULT_IMAGE_BYTES = 16 * 1024 * 1024
FALLBACK_RESPONSES_MODEL = "gpt-5"
IMAGE_TOOL_MODELS = {
    "gpt-image-1",
    "gpt-image-1-mini",
    "gpt-image-1.5",
    "gpt-image-2",
    "chatgpt-image-latest",
}
RESPONSES_IMAGE_MODELS = {
    "gpt-6-astra",
    "gpt-5.5",
    "gpt-5.4-mini",
    "gpt-5.4-nano",
    "gpt-5.2",
    "gpt-5",
    "gpt-5-nano",
    "o3",
    "gpt-4.1",
    "gpt-4.1-mini",
    "gpt-4.1-nano",
    "gpt-4o",
    "gpt-4o-mini",
}


class ImageGenerationRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=2000)

    @field_validator("prompt")
    @classmethod
    def clean_prompt(cls, value: str) -> str:
        clean = value.strip()
        if not clean:
            raise ValueError("Describe the image you want LJ AI to create.")
        return clean


class MobileImageEditRequest(ImageGenerationRequest):
    image_base64: str = Field(min_length=100, max_length=12_000_000)
    media_type: Literal["image/png", "image/jpeg", "image/webp"] = "image/png"


def _image_media_type(image_bytes: bytes) -> str | None:
    if image_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if image_bytes.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if len(image_bytes) >= 12 and image_bytes[:4] == b"RIFF" and image_bytes[8:12] == b"WEBP":
        return "image/webp"
    return None


def _decode_base64_image(
    value: str,
    *,
    maximum_bytes: int,
    invalid_detail: str,
    declared_media_type: str | None = None,
) -> tuple[str, str]:
    """Return canonical base64 and the signature-derived media type."""
    encoded = value.strip()
    data_url_media_type: str | None = None
    if encoded.casefold().startswith("data:"):
        header, separator, encoded = encoded.partition(",")
        if not separator or ";base64" not in header.casefold():
            raise HTTPException(status_code=422, detail=invalid_detail)
        data_url_media_type = header[5:].split(";", 1)[0].strip().casefold()
    # Accept harmless line wrapping but always return a compact canonical value.
    encoded = "".join(encoded.split())
    try:
        image_bytes = base64.b64decode(encoded, validate=True)
    except (TypeError, ValueError):
        raise HTTPException(status_code=422, detail=invalid_detail) from None
    if not image_bytes:
        raise HTTPException(status_code=422, detail=invalid_detail)
    if len(image_bytes) > maximum_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"The image is too large. Choose one smaller than {maximum_bytes // (1024 * 1024)} MB.",
        )
    detected_media_type = _image_media_type(image_bytes)
    if detected_media_type is None:
        raise HTTPException(status_code=422, detail="The file is not a valid JPG, PNG or WebP image.")
    expected_media_type = (data_url_media_type or declared_media_type or "").casefold()
    if expected_media_type and expected_media_type != detected_media_type:
        raise HTTPException(status_code=422, detail="The attached image type does not match its contents.")
    return base64.b64encode(image_bytes).decode("ascii"), detected_media_type


def _configured_image_models(image_model: str, image_tool_model: str) -> tuple[str, str | None]:
    """Separate the mainline Responses model from the hosted GPT Image model."""
    configured = image_model.strip()
    configured_tool = image_tool_model.strip()
    if configured in IMAGE_TOOL_MODELS or configured.startswith(("gpt-image-", "chatgpt-image-")):
        # Backward compatibility: old deployments stored the GPT Image model in
        # OPENAI_IMAGE_MODEL rather than the dedicated tool-model variable.
        responses_model = FALLBACK_RESPONSES_MODEL
        tool_model = configured
    else:
        looks_like_mainline = (
            configured in RESPONSES_IMAGE_MODELS
            or configured.startswith(("gpt-5", "gpt-6", "o3", "o4"))
            or any(configured.startswith(f"{model}-20") for model in RESPONSES_IMAGE_MODELS)
        )
        responses_model = configured if looks_like_mainline else FALLBACK_RESPONSES_MODEL
        tool_model = configured_tool
    if tool_model and not tool_model.startswith(("gpt-image-", "chatgpt-image-")):
        tool_model = None
    return responses_model, tool_model or None


def _is_model_compatibility_error(error: HTTPException) -> bool:
    detail = str(error.detail).casefold()
    if "tools[0].model" in detail and any(
        phrase in detail for phrase in ("unknown parameter", "unsupported parameter", "extra input")
    ):
        return True
    return "model" in detail and any(
        phrase in detail
        for phrase in (
            "does not support",
            "not supported",
            "not found",
            "does not exist",
            "does not have access",
            "has no access",
            "not available",
            "not compatible",
            "invalid model",
            "unknown model",
        )
    )


async def _run_image_tool(
    *,
    openai_json: Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]],
    image_model: str,
    image_tool_model: str,
    action: Literal["generate", "edit"],
    prompt: str,
    source_data_url: str | None = None,
) -> tuple[dict[str, Any], str]:
    responses_model, tool_model = _configured_image_models(image_model, image_tool_model)
    content: list[dict[str, Any]] = [{"type": "input_text", "text": prompt}]
    if source_data_url:
        content.append({"type": "input_image", "image_url": source_data_url, "detail": "high"})
    instructions = (
        "Create one polished original image that closely follows the user's request. "
        "Return the finished image, not a textual description of it."
        if action == "generate"
        else (
            "Edit the attached user-provided image exactly as requested. Preserve subjects, identity, "
            "composition and details that the user did not ask to change. Return one finished image, "
            "not instructions or a textual description."
        )
    )
    attempts: list[tuple[str, str | None]] = [(responses_model, tool_model)]
    # Accounts may not yet have access to the explicitly selected GPT Image
    # tool model. Let the Responses API select its supported default next.
    if tool_model:
        attempts.append((responses_model, None))
    if responses_model != FALLBACK_RESPONSES_MODEL:
        attempts.append((FALLBACK_RESPONSES_MODEL, None))

    last_error: HTTPException | None = None
    seen: set[tuple[str, str | None]] = set()
    for attempt_model, attempt_tool_model in attempts:
        if (attempt_model, attempt_tool_model) in seen:
            continue
        seen.add((attempt_model, attempt_tool_model))
        tool: dict[str, Any] = {
            "type": "image_generation",
            "action": action,
            # PNG is the tool's default and matches Android's viewer/save flow.
            "quality": "high" if action == "edit" else "auto",
        }
        if attempt_tool_model:
            tool["model"] = attempt_tool_model
        payload: dict[str, Any] = {
            "model": attempt_model,
            "instructions": instructions,
            "input": [{"role": "user", "content": content}],
            "tools": [tool],
            "tool_choice": {"type": "image_generation"},
        }
        try:
            return await openai_json("responses", payload), attempt_model
        except HTTPException as error:
            last_error = error
            # Retry only explicit model/tool compatibility failures. Policy,
            # authentication, quota and transient upstream failures propagate.
            if not _is_model_compatibility_error(error):
                raise
    if last_error is not None:
        raise last_error
    raise HTTPException(status_code=502, detail="No compatible image model is configured.")


def _result_image(data: dict[str, Any]) -> tuple[str, str, str]:
    image_call = next(
        (
            item
            for item in data.get("output") or []
            if isinstance(item, dict)
            and item.get("type") == "image_generation_call"
            and isinstance(item.get("result"), str)
            and str(item.get("result") or "").strip()
        ),
        None,
    )
    if image_call is None:
        detail = ""
        for item in data.get("output") or []:
            if not isinstance(item, dict):
                continue
            error = item.get("error")
            if isinstance(error, str) and error.strip():
                detail = error.strip()[:400]
                break
            if isinstance(error, dict):
                detail = str(error.get("message") or "").strip()[:400]
                if detail:
                    break
        raise HTTPException(status_code=502, detail=detail or "The image service returned no finished image.")
    try:
        encoded, media_type = _decode_base64_image(
            str(image_call["result"]),
            maximum_bytes=MAX_RESULT_IMAGE_BYTES,
            invalid_detail="The image service returned invalid image data.",
        )
    except HTTPException as error:
        raise HTTPException(status_code=502, detail="The image service returned invalid image data.") from error
    if media_type != "image/png":
        raise HTTPException(status_code=502, detail="The image service returned an unsupported image format.")
    return encoded, media_type, str(image_call.get("revised_prompt") or "")[:2000]


def _usage(data: dict[str, Any]) -> tuple[int, int]:
    usage = data.get("usage") or {}
    return int(usage.get("input_tokens") or 0), int(usage.get("output_tokens") or 0)


def create_image_generation_router(
    *,
    current_identity: Callable[..., Awaitable[Any]],
    limiter: Any,
    check_image_allowance: Callable[[Any], Awaitable[dict[str, Any]]],
    consume_image_allowance: Callable[[Any], Awaitable[dict[str, Any]]],
    openai_json: Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]],
    record_api_usage: Callable[..., Awaitable[None]],
    save_chat_log: Callable[..., Awaitable[None]],
    image_model: str,
    image_tool_model: str,
    image_plans: set[str],
) -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["mobile-images"])

    async def create_or_edit(
        *,
        identity: Any,
        prompt: str,
        action: Literal["generate", "edit"],
        source_data_url: str | None = None,
    ) -> dict[str, Any]:
        if identity.effective_plan not in image_plans:
            action_name = "creation" if action == "generate" else "editing"
            raise HTTPException(status_code=403, detail=f"Image {action_name} is unavailable for this account.")
        await limiter.enforce(f"image-{action}:{identity.user_id}", 6, 60)
        # Check first so an exhausted account does not create an upstream image.
        # Consume only after the service has returned a fully decoded, validated
        # image; transient/model/policy failures must not use customer allowance.
        await check_image_allowance(identity)
        data, responses_model = await _run_image_tool(
            openai_json=openai_json,
            image_model=image_model,
            image_tool_model=image_tool_model,
            action=action,
            prompt=prompt,
            source_data_url=source_data_url,
        )
        image_base64, media_type, revised_prompt = _result_image(data)
        allowance = await consume_image_allowance(identity)
        input_tokens, output_tokens = _usage(data)
        await record_api_usage(
            identity.user_id,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )
        log_prefix = "Image generation" if action == "generate" else "Image edit"
        await save_chat_log(
            identity,
            f"[{log_prefix}] {prompt}",
            "[Image created and returned to the user's phone]",
            responses_model,
            input_tokens,
            output_tokens,
            False,
        )
        return {
            "image_base64": image_base64,
            "media_type": media_type,
            "revised_prompt": revised_prompt,
            "model": responses_model,
            "messages_used": allowance.get("messages_used", allowance.get("text_used")),
            "daily_limit": allowance.get("text_limit"),
            "images_used": allowance.get("images_used", allowance.get("image_used")),
            "image_limit": allowance.get("image_limit"),
            "allowance": allowance,
        }

    @router.post("/images/generate")
    async def generate_image(
        body: ImageGenerationRequest,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        return await create_or_edit(
            identity=identity,
            prompt=body.prompt,
            action="generate",
        )

    @router.post("/images/mobile/edit")
    async def edit_mobile_image(
        body: MobileImageEditRequest,
        identity: Any = Depends(current_identity),
    ) -> dict[str, Any]:
        image_base64, media_type = _decode_base64_image(
            body.image_base64,
            maximum_bytes=MAX_SOURCE_IMAGE_BYTES,
            invalid_detail="The attached image is invalid.",
            declared_media_type=body.media_type,
        )
        return await create_or_edit(
            identity=identity,
            prompt=body.prompt,
            action="edit",
            source_data_url=f"data:{media_type};base64,{image_base64}",
        )

    return router
