"""Load/save encrypted vault JSON."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from devsecret.crypto import VaultCryptoError, decrypt_vault, encrypt_vault

DEFAULT_API_KEY_EXPIRY_DAYS = 90
API_KEY_EXPIRY_WARN_DAYS = 14

EMPTY_VAULT: dict[str, Any] = {
    "settings": {"auto_delete_expired_api_keys": False},
    "api_keys": {},
    "recovery_codes": {},
}

INDEX_VERSION_V1 = 1
INDEX_VERSION = 2


def api_key_index_path(vault_path: Path) -> Path:
    """Plaintext sidecar listing API key (site, username) pairs — no secrets."""
    return vault_path.with_suffix(vault_path.suffix + ".index.json")


def vault_settings(data: dict[str, Any]) -> dict[str, Any]:
    s = data.get("settings")
    if isinstance(s, dict):
        return {
            "auto_delete_expired_api_keys": bool(
                s.get("auto_delete_expired_api_keys", False)
            ),
        }
    return {"auto_delete_expired_api_keys": False}


def default_api_key_expiry_string() -> str:
    d = datetime.now(timezone.utc).date() + timedelta(days=DEFAULT_API_KEY_EXPIRY_DAYS)
    return d.isoformat()


def parse_expiry_date(expiry: str) -> date | None:
    if not expiry or not isinstance(expiry, str):
        return None
    s = expiry.strip()
    if len(s) < 10:
        return None
    try:
        return date.fromisoformat(s[:10])
    except ValueError:
        return None


def utc_today() -> date:
    return datetime.now(timezone.utc).date()


def prune_expired_api_keys(data: dict[str, Any]) -> int:
    """Remove expired API key entries if vault setting is enabled. Returns count removed."""
    if not vault_settings(data)["auto_delete_expired_api_keys"]:
        return 0
    today = utc_today()
    api = data.get("api_keys")
    if not isinstance(api, dict):
        return 0
    removed = 0
    for site in list(api.keys()):
        users = api[site]
        if not isinstance(users, dict):
            continue
        for user in list(users.keys()):
            entry = users.get(user)
            if not isinstance(entry, dict):
                continue
            exp = parse_expiry_date(entry.get("expiry") or "")
            if exp is not None and exp < today:
                del users[user]
                removed += 1
        if not users:
            del api[site]
    return removed


@dataclass(frozen=True)
class ApiKeyIndex:
    """Plaintext index for list-keys (no API key material)."""

    auto_delete_expired_api_keys: bool
    # site -> username -> expiry string (may be empty if unknown / legacy)
    api_keys: dict[str, dict[str, str]]


def _api_key_index_payload(data: dict[str, Any]) -> dict[str, Any]:
    normalized = _normalize(data)
    auto_del = vault_settings(normalized)["auto_delete_expired_api_keys"]
    api_keys = normalized.get("api_keys", {})
    sites: dict[str, dict[str, str]] = {}
    if isinstance(api_keys, dict):
        for site, users in api_keys.items():
            if not isinstance(users, dict):
                continue
            sites[site] = {}
            for user, entry in users.items():
                if isinstance(entry, dict):
                    sites[site][user] = (entry.get("expiry") or "") if isinstance(
                        entry.get("expiry"), str
                    ) else ""
                else:
                    sites[site][user] = ""
    return {
        "version": INDEX_VERSION,
        "auto_delete_expired_api_keys": auto_del,
        "api_keys": sites,
    }


def write_api_key_index(vault_path: Path, data: dict[str, Any]) -> None:
    payload = _api_key_index_payload(data)
    p = api_key_index_path(vault_path)
    p.write_text(json.dumps(payload, ensure_ascii=False) + "\n", encoding="utf-8")


def read_api_key_index(vault_path: Path) -> ApiKeyIndex:
    p = api_key_index_path(vault_path)
    if not p.is_file():
        raise VaultCryptoError(
            "API key listing index is missing (expected next to the vault). "
            "Save the vault once with a command that writes it (e.g. add-key, add-recovery, init)."
        )
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        raise VaultCryptoError(f"Could not read API key index: {e}") from e
    if not isinstance(raw, dict):
        raise VaultCryptoError("Corrupt API key index.")

    ver = raw.get("version")
    if ver == INDEX_VERSION_V1:
        return _parse_index_v1(raw)
    if ver == INDEX_VERSION:
        return _parse_index_v2(raw)
    raise VaultCryptoError("Unsupported or corrupt API key index file.")


def _parse_index_v1(raw: dict[str, Any]) -> ApiKeyIndex:
    keys = raw.get("api_keys")
    if not isinstance(keys, dict):
        raise VaultCryptoError("Corrupt API key index (api_keys).")
    out: dict[str, dict[str, str]] = {}
    for site, names in keys.items():
        if isinstance(names, list) and all(isinstance(x, str) for x in names):
            out[str(site)] = {u: "" for u in names}
        else:
            raise VaultCryptoError("Corrupt API key index (user lists).")
    return ApiKeyIndex(
        auto_delete_expired_api_keys=False,
        api_keys=out,
    )


def _parse_index_v2(raw: dict[str, Any]) -> ApiKeyIndex:
    auto_del = bool(raw.get("auto_delete_expired_api_keys", False))
    keys = raw.get("api_keys")
    if not isinstance(keys, dict):
        raise VaultCryptoError("Corrupt API key index (api_keys).")
    out: dict[str, dict[str, str]] = {}
    for site, users in keys.items():
        if not isinstance(users, dict):
            raise VaultCryptoError("Corrupt API key index (nested users).")
        out[str(site)] = {}
        for user, exp in users.items():
            if isinstance(exp, str):
                out[str(site)][str(user)] = exp
            else:
                out[str(site)][str(user)] = ""
    return ApiKeyIndex(
        auto_delete_expired_api_keys=auto_del,
        api_keys=out,
    )


def _normalize(data: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "settings": dict(EMPTY_VAULT["settings"]),
        "api_keys": {},
        "recovery_codes": {},
    }
    if "settings" in data and isinstance(data["settings"], dict):
        out["settings"]["auto_delete_expired_api_keys"] = bool(
            data["settings"].get("auto_delete_expired_api_keys", False)
        )
    if "api_keys" in data and isinstance(data["api_keys"], dict):
        out["api_keys"] = data["api_keys"]
    if "recovery_codes" in data and isinstance(data["recovery_codes"], dict):
        out["recovery_codes"] = data["recovery_codes"]
    return out


def load(path: Path, password: str) -> dict[str, Any]:
    raw = path.read_bytes()
    plain = decrypt_vault(password, raw)
    try:
        data = json.loads(plain.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise VaultCryptoError("Vault plaintext is not valid UTF-8 JSON.") from e
    if not isinstance(data, dict):
        raise VaultCryptoError("Vault root must be a JSON object.")
    return _normalize(data)


def save(path: Path, password: str, data: dict[str, Any]) -> None:
    normalized = _normalize(data)
    blob = encrypt_vault(password, json.dumps(normalized, ensure_ascii=False).encode("utf-8"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)
    write_api_key_index(path, normalized)
