from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from backend.api.auth import require_session
from backend.llama_service import answer_security_question, get_llama_status

router = APIRouter()


class CopilotRequest(BaseModel):
    question: str = Field(min_length=3, max_length=1200)
    current_page: str = Field(default="Dashboard", min_length=1, max_length=80)
    context: dict[str, Any] = Field(default_factory=dict)


@router.get("/status")
def ai_status(authorization: str | None = Header(default=None)):
    require_session(authorization)
    return get_llama_status()


@router.post("/ask")
def ask_copilot(
    payload: CopilotRequest,
    authorization: str | None = Header(default=None),
):
    require_session(authorization)
    if len(json.dumps(payload.context, default=str)) > 12000:
        raise HTTPException(status_code=413, detail="Security context is too large")
    return answer_security_question(payload.question, payload.current_page, payload.context)
