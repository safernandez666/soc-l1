"""Session-bound pseudonymizer for PII fields shipped to the LLM."""
from __future__ import annotations

import hashlib
from typing import Any

# Map known Wazuh/ECS-style field names to canonical categories so that
# semantically equivalent fields share a namespace (e.g. ``srcip`` and
# ``dstip`` both pseudonymize under ``ip_``).
_FIELD_CATEGORY: dict[str, str] = {
    "srcip": "ip",
    "dstip": "ip",
    "src_ip": "ip",
    "dst_ip": "ip",
    "source.ip": "ip",
    "destination.ip": "ip",
}


class Pseudonymizer:
    def __init__(self, *, salt: str) -> None:
        self._salt = salt
        self._encode_map: dict[tuple[str, str], str] = {}
        self._decode_map: dict[str, str] = {}

    def encode(self, category: str, value: str) -> str:
        key = (category, value)
        if key in self._encode_map:
            return self._encode_map[key]
        digest = hashlib.sha256(
            f"{self._salt}:{category}:{value}".encode()
        ).hexdigest()[:8]
        prefix = category.replace(".", "_").lower()
        token = f"{prefix}_{digest}"
        self._encode_map[key] = token
        self._decode_map[token] = value
        return token

    def decode(self, token: str) -> str | None:
        return self._decode_map.get(token)

    def mask(self, obj: dict[str, Any], *, fields: list[str]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if k in fields and isinstance(v, str):
                category = _FIELD_CATEGORY.get(k, k)
                out[k] = self.encode(category, v)
            else:
                out[k] = v
        return out
