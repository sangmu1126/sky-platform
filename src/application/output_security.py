"""Output-only secret minimization; never a proof arbitrary data is secret-free.

Used before model context, public JSON, event persistence and logging. Does not
rewrite signed artifacts, authorization headers or credential storage.
"""

import base64
import json
import os
import re
from urllib.parse import quote

_ENV_SECRETS = {
    "OPENAI_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "SKY_GITHUB_APP_PRIVATE_KEY",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "PGPASSWORD",
    "DATABASE_URL",
    "SKY_SECURITY_SIGNING_PRIVATE_KEY",
}


def redact(text: str, *, values=()) -> str:
    known = {v for v in values if isinstance(v, str) and v}
    known.update(os.environ[n] for n in _ENV_SECRETS if os.environ.get(n))
    variants = set()
    for value in known:
        variants.add(value)
        if len(value) >= 8:
            variants.update(
                (
                    quote(value, safe=""),
                    json.dumps(value)[1:-1],
                    base64.b64encode(value.encode()).decode(),
                    base64.urlsafe_b64encode(value.encode()).decode(),
                )
            )
    for value in sorted(variants, key=len, reverse=True):
        text = text.replace(value, "[REDACTED]")
    # Redact an unterminated key too; bounded reads may end before its END marker.
    text = re.sub(
        r"-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|\Z)",
        "[REDACTED_PRIVATE_KEY]",
        text,
        flags=re.S,
    )
    text = re.sub(
        r"\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,}|github_pat_[A-Za-z0-9_]{12,}|(?:AKIA|ASIA)[A-Z0-9]{16})\b",
        "[REDACTED_TOKEN]",
        text,
    )
    text = re.sub(
        r"(?i)((?:https?|postgres(?:ql)?|rediss?|mongodb(?:\+srv)?|mysql)://)[^\s/@]+@",
        r"\1[REDACTED]@",
        text,
    )
    text = re.sub(
        r"""(?i)(["']?[\w-]*(?:secret|password|api[_-]?key|token)[\w-]*["']?\s*[:=]\s*)(["'])([^\n]*?)\2""",
        lambda m: m[1] + m[2] + "[REDACTED]" + m[2],
        text,
    )
    text = re.sub(
        r"(?im)^(\s*(?:export\s+)?[A-Z_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|ACCESS_KEY)[A-Z_]*\s*=\s*)([^\s\"'\r\n#]+)",
        lambda m: m[1] + "[REDACTED]",
        text,
    )
    text = re.sub(r"(?i)(\b(?:Bearer|Basic)\s+)[A-Za-z0-9._~+/=-]{8,}", r"\1[REDACTED]", text)
    text = re.sub(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[REDACTED_JWT]", text)
    text = re.sub(
        r"(?i)([?&](?:access_token|api_key|password|secret|signature)=)[^&\s\"<>]+", r"\1[REDACTED]", text
    )
    return text


def public_value(value):
    """Sanitize JSON strings, preserving numeric/boolean fields and safe references."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [public_value(item) for item in value]
    if isinstance(value, tuple):
        return [public_value(item) for item in value]
    if isinstance(value, dict):
        return {
            redact(key) if isinstance(key, str) else key: public_value(item) for key, item in value.items()
        }
    return value
