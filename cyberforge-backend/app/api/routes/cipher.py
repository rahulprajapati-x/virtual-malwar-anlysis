"""
CyberForge — CIPHER AI Assistant Route
Proxies chat requests to Claude with full sample analysis context injected.
Keeps the Anthropic API key server-side (never exposed to frontend).
"""
import os
import logging
import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.models import Sample
from app.schemas.schemas import CipherChatRequest, CipherChatResponse, ExplainRequest, ExplainResponse

logger = logging.getLogger("cyberforge.api.cipher")
router = APIRouter(prefix="/api/cipher", tags=["CIPHER AI"])

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = "claude-sonnet-4-6"


CIPHER_SYSTEM_PROMPT = """You are CIPHER — an elite AI Cyber Investigation Assistant deployed for \
law enforcement cybercrime units, CERT teams, SOC analysts, and digital forensics investigators.

You have deep expertise in:
- Malware analysis (static & dynamic), reverse engineering concepts
- Digital forensics and incident response (DFIR)
- MITRE ATT&CK framework and threat actor TTPs
- Threat intelligence correlation (APT groups, malware families, C2 infrastructure)
- Indian and international cybercrime law and evidence handling procedures

Your responses are authoritative, precise, and action-oriented — written in an intelligence \
briefing style. You cite MITRE ATT&CK technique IDs where relevant. You think like a senior \
threat analyst helping investigators triage incidents quickly and accurately.

Format responses with clear structure using bullet points for lists when helpful. Be specific \
and technical, but accessible to investigators who may not have deep malware RE background. \
Always end substantive responses with concrete, actionable next steps for the investigator.

{context}
"""


def _build_context(sample: Sample | None) -> str:
    if not sample or not sample.analysis_data:
        return "No active sample analysis is loaded. Answer from general cyber threat intelligence knowledge."

    data = sample.analysis_data
    yara = data.get("yara", {})
    iocs = data.get("iocs", {})
    mitre = data.get("mitre", [])
    behaviors = data.get("behaviors", [])
    vt = data.get("virustotal")

    lines = [
        "ACTIVE ANALYSIS CONTEXT (use this to answer investigator questions):",
        f"File: {sample.filename} | Type: {sample.file_type} | Size: {sample.file_size} bytes",
        f"SHA-256: {sample.sha256}",
        f"Risk Score: {sample.risk_score}/100 | Threat Level: {sample.threat_level}",
    ]

    if yara.get("matches"):
        rules = ", ".join(m["rule"] for m in yara["matches"][:8])
        lines.append(f"YARA Matches: {rules}")

    if vt and vt.get("found"):
        lines.append(f"VirusTotal: {vt['detection_ratio']} engines flagged malicious ({vt['verdict']})")
        if vt.get("threat_names"):
            lines.append(f"VT Threat Names: {', '.join(vt['threat_names'][:5])}")

    if iocs.get("domains"):
        lines.append(f"C2/Malicious Domains: {', '.join(iocs['domains'][:5])}")
    if iocs.get("ips"):
        lines.append(f"Malicious IPs: {', '.join(iocs['ips'][:5])}")
    if iocs.get("crypto_wallets"):
        lines.append(f"Crypto Wallets: {', '.join(iocs['crypto_wallets'][:3])}")

    if mitre:
        techniques = ", ".join(f"{t['id']}({t['name']})" for t in mitre[:8])
        lines.append(f"MITRE ATT&CK Techniques: {techniques}")

    if behaviors:
        titles = " | ".join(b["title"] for b in behaviors[:6])
        lines.append(f"Key Behaviors: {titles}")

    return "\n".join(lines)


@router.post("/chat", response_model=CipherChatResponse)
async def chat(payload: CipherChatRequest, db: Session = Depends(get_db)):
    """
    Send a message to CIPHER (Claude-powered investigation assistant).
    If sample_id is provided, full analysis context is injected automatically.
    """
    if not ANTHROPIC_API_KEY:
        raise HTTPException(500, "ANTHROPIC_API_KEY not configured on server")

    sample = None
    if payload.sample_id:
        sample = db.query(Sample).filter(Sample.id == payload.sample_id).first()

    system_prompt = CIPHER_SYSTEM_PROMPT.format(context=_build_context(sample))

    api_messages = [
        {"role": m.role, "content": m.content}
        for m in payload.messages
        if m.role in ("user", "assistant")
    ][-20:]  # cap context window

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json={
                    "model": ANTHROPIC_MODEL,
                    "max_tokens": 1200,
                    "system": system_prompt,
                    "messages": api_messages,
                },
            )
            resp.raise_for_status()
            data = resp.json()

        reply = ""
        for block in data.get("content", []):
            if block.get("type") == "text":
                reply += block["text"]

        if not reply:
            reply = "CIPHER could not generate a response. Please retry."

        return CipherChatResponse(reply=reply)

    except httpx.HTTPStatusError as e:
        logger.error(f"Anthropic API error: {e.response.status_code} {e.response.text}")
        raise HTTPException(502, f"AI service error: {e.response.status_code}")
    except httpx.TimeoutException:
        raise HTTPException(504, "AI service timed out")
    except Exception as e:
        logger.error(f"CIPHER chat error: {e}")
        raise HTTPException(500, f"Internal error: {str(e)}")


EXPLAIN_SYSTEM_PROMPT = """You are a senior digital forensics and threat intelligence analyst.
You have been asked to brief a junior analyst on a specific {item_type} finding: '{item_value}'.
Context: {context}

Provide a concise, highly technical but accessible explanation.
Format your response using Markdown. Structure your response EXACTLY with these headings:
1. **What it is**: (Brief definition)
2. **Mechanism of Action**: (Why it's dangerous or how it's used in an attack chain)
3. **Attribution & Usage**: (Common malware families or APTs that use this)
4. **Investigator Next Steps**: (Concrete actions to contain or hunt)

Keep it under 250 words total. Do not include generic greetings.
"""

@router.post("/explain", response_model=ExplainResponse)
async def explain_indicator(payload: ExplainRequest):
    """
    Generate a concise, actionable explanation for a specific threat indicator.
    """
    if not ANTHROPIC_API_KEY:
        raise HTTPException(500, "ANTHROPIC_API_KEY not configured on server")

    ctx = payload.context or "No additional context."
    system_prompt = EXPLAIN_SYSTEM_PROMPT.format(
        item_type=payload.item_type,
        item_value=payload.item_value,
        context=ctx
    )

    try:
        async with httpx.AsyncClient(timeout=25.0) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json={
                    "model": ANTHROPIC_MODEL,
                    "max_tokens": 500,
                    "system": system_prompt,
                    "messages": [{"role": "user", "content": f"Please explain the significance of this {payload.item_type}: {payload.item_value}"}],
                },
            )
            resp.raise_for_status()
            data = resp.json()

        explanation = ""
        for block in data.get("content", []):
            if block.get("type") == "text":
                explanation += block["text"]

        if not explanation:
            explanation = "CIPHER could not generate an explanation. Please try again."

        return ExplainResponse(explanation=explanation.strip())

    except httpx.HTTPStatusError as e:
        logger.error(f"Anthropic API error (explain): {e.response.status_code} {e.response.text}")
        raise HTTPException(502, f"AI service error: {e.response.status_code}")
    except httpx.TimeoutException:
        raise HTTPException(504, "AI service timed out")
    except Exception as e:
        logger.error(f"CIPHER explain error: {e}")
        raise HTTPException(500, f"Internal error: {str(e)}")
