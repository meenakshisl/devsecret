"""Tests for devsecret.vault."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

from devsecret.crypto import VaultCryptoError, encrypt_vault
from devsecret.vault import (
    EMPTY_VAULT,
    INDEX_VERSION,
    INDEX_VERSION_V1,
    api_key_index_path,
    default_api_key_expiry_string,
    load,
    parse_expiry_date,
    prune_expired_api_keys,
    read_api_key_index,
    save,
    utc_today,
    vault_settings,
)

from tests.constants import (
    DUMMY_API_KEY,
    DUMMY_PASSWORD,
    DUMMY_RECOVERY,
    DUMMY_SITE,
    DUMMY_USER,
)


def test_vault_save_load_empty(tmp_vault: Path):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    data = load(tmp_vault, DUMMY_PASSWORD)
    assert data["api_keys"] == {}
    assert data["recovery_codes"] == {}
    assert vault_settings(data)["auto_delete_expired_api_keys"] is False


def test_vault_api_key_and_recovery_roundtrip(tmp_vault: Path):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    data = load(tmp_vault, DUMMY_PASSWORD)
    data["api_keys"][DUMMY_SITE] = {
        DUMMY_USER: {"api_key": DUMMY_API_KEY, "expiry": "2099-12-31"},
    }
    data["recovery_codes"][DUMMY_SITE] = {DUMMY_USER: list(DUMMY_RECOVERY)}
    save(tmp_vault, DUMMY_PASSWORD, data)

    again = load(tmp_vault, DUMMY_PASSWORD)
    assert again["api_keys"][DUMMY_SITE][DUMMY_USER]["api_key"] == DUMMY_API_KEY
    assert again["recovery_codes"][DUMMY_SITE][DUMMY_USER] == DUMMY_RECOVERY


def test_sidecar_index_written(tmp_vault: Path):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    idx_path = api_key_index_path(tmp_vault)
    assert idx_path.is_file()
    raw = json.loads(idx_path.read_text(encoding="utf-8"))
    assert raw["version"] == INDEX_VERSION
    assert "auto_delete_expired_api_keys" in raw


def test_read_legacy_v1_index(tmp_vault: Path):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    idx_path = api_key_index_path(tmp_vault)
    legacy = {
        "version": INDEX_VERSION_V1,
        "api_keys": {DUMMY_SITE: [DUMMY_USER]},
    }
    idx_path.write_text(json.dumps(legacy) + "\n", encoding="utf-8")
    idx = read_api_key_index(tmp_vault)
    assert idx.api_keys[DUMMY_SITE][DUMMY_USER] == ""
    assert idx.auto_delete_expired_api_keys is False


def test_prune_expired_api_keys_when_enabled(tmp_vault: Path):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    data = load(tmp_vault, DUMMY_PASSWORD)
    past = (utc_today() - timedelta(days=2)).isoformat()
    data["api_keys"][DUMMY_SITE] = {
        DUMMY_USER: {"api_key": DUMMY_API_KEY, "expiry": past},
    }
    data["settings"]["auto_delete_expired_api_keys"] = True
    assert prune_expired_api_keys(data) == 1
    assert data["api_keys"] == {}


def test_prune_noop_when_auto_delete_off(tmp_vault: Path):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    data = load(tmp_vault, DUMMY_PASSWORD)
    past = (utc_today() - timedelta(days=2)).isoformat()
    data["api_keys"][DUMMY_SITE] = {
        DUMMY_USER: {"api_key": DUMMY_API_KEY, "expiry": past},
    }
    assert prune_expired_api_keys(data) == 0
    assert DUMMY_USER in data["api_keys"][DUMMY_SITE]


def test_default_expiry_string_is_future_iso_date():
    s = default_api_key_expiry_string()
    d = parse_expiry_date(s)
    assert d is not None
    assert d > utc_today()


def test_parse_expiry_accepts_prefix():
    assert parse_expiry_date("2030-06-15T00:00:00Z") == parse_expiry_date("2030-06-15")


def test_vault_settings_missing_or_invalid():
    assert vault_settings({})["auto_delete_expired_api_keys"] is False
    assert vault_settings({"settings": "not-a-dict"})["auto_delete_expired_api_keys"] is False


def test_parse_expiry_date_edge_cases():
    assert parse_expiry_date(None) is None  # type: ignore[arg-type]
    assert parse_expiry_date("") is None
    assert parse_expiry_date("   ") is None
    assert parse_expiry_date("2030-06-1") is None
    assert parse_expiry_date("not-a-date-xx") is None
    assert parse_expiry_date("2030-13-45") is None


def test_prune_api_keys_not_dict():
    data = {
        "settings": {"auto_delete_expired_api_keys": True},
        "api_keys": [],
    }
    assert prune_expired_api_keys(data) == 0


def test_prune_skips_non_dict_entry():
    data = {
        "settings": {"auto_delete_expired_api_keys": True},
        "api_keys": {DUMMY_SITE: {DUMMY_USER: "not-a-dict"}},
    }
    assert prune_expired_api_keys(data) == 0


def test_prune_empty_expiry_not_removed():
    data = {
        "settings": {"auto_delete_expired_api_keys": True},
        "api_keys": {
            DUMMY_SITE: {DUMMY_USER: {"api_key": "x", "expiry": ""}},
        },
    }
    assert prune_expired_api_keys(data) == 0
    assert DUMMY_USER in data["api_keys"][DUMMY_SITE]


def test_prune_removes_empty_site_after_last_user():
    data = {
        "settings": {"auto_delete_expired_api_keys": True},
        "api_keys": {
            DUMMY_SITE: {
                "u1": {
                    "api_key": "a",
                    "expiry": (utc_today() - timedelta(days=1)).isoformat(),
                },
            },
        },
    }
    assert prune_expired_api_keys(data) == 1
    assert DUMMY_SITE not in data["api_keys"]


def test_prune_malformed_users_dict_skipped():
    data = {
        "settings": {"auto_delete_expired_api_keys": True},
        "api_keys": {DUMMY_SITE: []},
    }
    assert prune_expired_api_keys(data) == 0


def test_load_invalid_json(tmp_path: Path):
    p = tmp_path / "v.enc"
    p.write_bytes(encrypt_vault(DUMMY_PASSWORD, b"{not json"))
    with pytest.raises(VaultCryptoError, match="not valid UTF-8 JSON"):
        load(p, DUMMY_PASSWORD)


def test_load_non_utf8_plaintext(tmp_path: Path):
    p = tmp_path / "v.enc"
    p.write_bytes(encrypt_vault(DUMMY_PASSWORD, b"\xff\xfe"))
    with pytest.raises(VaultCryptoError, match="not valid UTF-8 JSON"):
        load(p, DUMMY_PASSWORD)


def test_load_json_root_not_object(tmp_path: Path):
    p = tmp_path / "v.enc"
    p.write_bytes(encrypt_vault(DUMMY_PASSWORD, b'"just a string"'))
    with pytest.raises(VaultCryptoError, match="must be a JSON object"):
        load(p, DUMMY_PASSWORD)


def test_normalize_drops_extra_top_level_keys(tmp_path: Path):
    p = tmp_path / "v.enc"
    p.write_bytes(
        encrypt_vault(
            DUMMY_PASSWORD,
            b'{"extra":1,"settings":{},"api_keys":{},"recovery_codes":{}}',
        )
    )
    data = load(p, DUMMY_PASSWORD)
    assert "extra" not in data


def test_normalize_partial_settings(tmp_path: Path):
    p = tmp_path / "v.enc"
    p.write_bytes(
        encrypt_vault(DUMMY_PASSWORD, b'{"settings":{},"api_keys":{},"recovery_codes":{}}')
    )
    data = load(p, DUMMY_PASSWORD)
    assert vault_settings(data)["auto_delete_expired_api_keys"] is False


def test_index_payload_non_string_expiry_in_entry(tmp_vault: Path):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    data = load(tmp_vault, DUMMY_PASSWORD)
    data["api_keys"][DUMMY_SITE] = {
        DUMMY_USER: {"api_key": DUMMY_API_KEY, "expiry": 12345},
    }
    save(tmp_vault, DUMMY_PASSWORD, data)
    raw = json.loads(api_key_index_path(tmp_vault).read_text(encoding="utf-8"))
    assert raw["api_keys"][DUMMY_SITE][DUMMY_USER] == ""


def test_read_api_key_index_missing(tmp_vault: Path):
    tmp_vault.write_bytes(b"not a real vault")
    with pytest.raises(VaultCryptoError, match="index is missing"):
        read_api_key_index(tmp_vault)


def test_read_api_key_index_invalid_json(tmp_vault: Path):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    api_key_index_path(tmp_vault).write_text("{broken\n", encoding="utf-8")
    with pytest.raises(VaultCryptoError, match="Could not read API key index"):
        read_api_key_index(tmp_vault)


def test_read_api_key_index_not_dict(tmp_vault: Path):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    api_key_index_path(tmp_vault).write_text("[1,2]", encoding="utf-8")
    with pytest.raises(VaultCryptoError, match="Corrupt API key index"):
        read_api_key_index(tmp_vault)


def test_read_api_key_index_unknown_version(tmp_vault: Path):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    api_key_index_path(tmp_vault).write_text(
        json.dumps({"version": 999, "api_keys": {}}) + "\n", encoding="utf-8"
    )
    with pytest.raises(VaultCryptoError, match="Unsupported or corrupt"):
        read_api_key_index(tmp_vault)


def test_read_api_key_index_v2_api_keys_not_dict(tmp_vault: Path):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    api_key_index_path(tmp_vault).write_text(
        json.dumps({"version": INDEX_VERSION, "api_keys": []}) + "\n", encoding="utf-8"
    )
    with pytest.raises(VaultCryptoError, match="api_keys"):
        read_api_key_index(tmp_vault)


def test_read_api_key_index_v2_nested_users_not_dict(tmp_vault: Path):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    api_key_index_path(tmp_vault).write_text(
        json.dumps({"version": INDEX_VERSION, "api_keys": {DUMMY_SITE: []}}) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(VaultCryptoError, match="nested users"):
        read_api_key_index(tmp_vault)


def test_read_api_key_index_v2_non_str_expiry_coerced(tmp_vault: Path):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    api_key_index_path(tmp_vault).write_text(
        json.dumps(
            {
                "version": INDEX_VERSION,
                "api_keys": {DUMMY_SITE: {DUMMY_USER: None}},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    idx = read_api_key_index(tmp_vault)
    assert idx.api_keys[DUMMY_SITE][DUMMY_USER] == ""


def test_read_api_key_index_v1_api_keys_not_dict(tmp_vault: Path):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    api_key_index_path(tmp_vault).write_text(
        json.dumps({"version": INDEX_VERSION_V1, "api_keys": []}) + "\n", encoding="utf-8"
    )
    with pytest.raises(VaultCryptoError, match="api_keys"):
        read_api_key_index(tmp_vault)


def test_read_api_key_index_v1_user_list_bad_element(tmp_vault: Path):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    api_key_index_path(tmp_vault).write_text(
        json.dumps({"version": INDEX_VERSION_V1, "api_keys": {DUMMY_SITE: [1, 2]}}) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(VaultCryptoError, match="user lists"):
        read_api_key_index(tmp_vault)
