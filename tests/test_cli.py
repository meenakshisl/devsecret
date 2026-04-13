"""Tests for devsecret.cli."""

from __future__ import annotations

import argparse
import io
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from devsecret import cli
from devsecret.vault import EMPTY_VAULT, load, parse_expiry_date, save, utc_today

from tests.constants import (
    DUMMY_API_KEY,
    DUMMY_PASSWORD,
    DUMMY_RECOVERY,
    DUMMY_SITE,
    DUMMY_USER,
)


def test_resolve_vault_path_explicit():
    p = cli.resolve_vault_path("/tmp/custom.enc")
    assert p == Path("/tmp/custom.enc")


def test_resolve_vault_path_env(monkeypatch):
    monkeypatch.setenv("DEVSECRET_VAULT", "~/env-vault.enc")
    p = cli.resolve_vault_path(None)
    assert p == Path("~/env-vault.enc").expanduser()


def test_resolve_vault_path_default_home(monkeypatch):
    monkeypatch.delenv("DEVSECRET_VAULT", raising=False)
    fake_home = Path("/fakehome")
    with patch.object(Path, "home", return_value=fake_home):
        p = cli.resolve_vault_path(None)
    assert p == fake_home / ".devsecret" / "vault.enc"


def test_read_master_password_empty_exits(capsys):
    with patch("getpass.getpass", return_value=""):
        with pytest.raises(SystemExit) as exc:
            cli.read_master_password()
    assert exc.value.code == 1
    assert "empty" in capsys.readouterr().err.lower()


def test_collect_recovery_codes_from_flags():
    out = cli.collect_recovery_codes(["a,b", "c"])
    assert out == ["a", "b", "c"]


def test_collect_recovery_codes_stdin_not_tty():
    fake_in = io.StringIO("line1\n\nline2\n")
    fake_in.isatty = lambda: False  # type: ignore[method-assign]
    with patch.object(cli.sys, "stdin", fake_in):
        got = cli.collect_recovery_codes(None)
    assert got == ["line1", "line2"]


def test_collect_recovery_codes_empty_exits():
    fake_in = io.StringIO("")
    fake_in.isatty = lambda: False  # type: ignore[method-assign]
    with patch.object(cli.sys, "stdin", fake_in):
        with pytest.raises(SystemExit) as exc:
            cli.collect_recovery_codes(None)
    assert exc.value.code == 1


def test_load_vault_maybe_prune_calls_save_when_prune(tmp_vault: Path):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    data = load(tmp_vault, DUMMY_PASSWORD)
    data["settings"]["auto_delete_expired_api_keys"] = True
    data["api_keys"][DUMMY_SITE] = {
        DUMMY_USER: {
            "api_key": "x",
            "expiry": (utc_today() - timedelta(days=1)).isoformat(),
        },
    }
    save(tmp_vault, DUMMY_PASSWORD, data)

    with patch("devsecret.cli.save") as mock_save:
        cli.load_vault_maybe_prune(tmp_vault, DUMMY_PASSWORD)
    mock_save.assert_called_once()


def test_warn_api_key_expiry_expired(capsys):
    past = (utc_today() - timedelta(days=3)).isoformat()
    cli.warn_api_key_expiry(DUMMY_SITE, DUMMY_USER, past)
    err = capsys.readouterr().err
    assert "expired" in err.lower()


def test_warn_api_key_expiry_today(capsys):
    cli.warn_api_key_expiry(DUMMY_SITE, DUMMY_USER, utc_today().isoformat())
    err = capsys.readouterr().err
    assert "today" in err.lower()


def test_warn_api_key_expiry_within_warn_window(capsys):
    soon = (utc_today() + timedelta(days=5)).isoformat()
    cli.warn_api_key_expiry(DUMMY_SITE, DUMMY_USER, soon)
    err = capsys.readouterr().err
    assert "day(s) left" in err


def test_warn_api_key_expiry_far_future_silent(capsys):
    far = (utc_today() + timedelta(days=100)).isoformat()
    cli.warn_api_key_expiry(DUMMY_SITE, DUMMY_USER, far)
    assert capsys.readouterr().err == ""


def test_warn_api_key_expiry_unparseable_silent(capsys):
    cli.warn_api_key_expiry(DUMMY_SITE, DUMMY_USER, "nope")
    assert capsys.readouterr().err == ""


def test_cmd_init_writes_vault(tmp_vault: Path):
    with patch("devsecret.cli.read_master_password", return_value=DUMMY_PASSWORD):
        cli.cmd_init(argparse.Namespace(vault=str(tmp_vault), force=False))
    assert tmp_vault.is_file()


def test_cmd_init_existing_no_force_exits(tmp_vault: Path):
    tmp_vault.write_text("x", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        cli.cmd_init(argparse.Namespace(vault=str(tmp_vault), force=False))
    assert exc.value.code == 1


def test_cmd_init_force_overwrites(tmp_vault: Path):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    with patch("devsecret.cli.read_master_password", return_value=DUMMY_PASSWORD):
        cli.cmd_init(argparse.Namespace(vault=str(tmp_vault), force=True))
    data = load(tmp_vault, DUMMY_PASSWORD)
    assert data["api_keys"] == {}


def test_cmd_add_key_uses_default_expiry_and_warns(tmp_vault: Path, capsys):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    ns = argparse.Namespace(
        vault=str(tmp_vault),
        site=DUMMY_SITE,
        username=DUMMY_USER,
        expiry=None,
        no_expiry=False,
    )
    with patch("devsecret.cli.read_master_password", return_value=DUMMY_PASSWORD):
        with patch("getpass.getpass", return_value=DUMMY_API_KEY):
            cli.cmd_add_key(ns)
    err = capsys.readouterr().err
    assert "default expiry" in err.lower() or "90" in err
    data = load(tmp_vault, DUMMY_PASSWORD)
    exp = data["api_keys"][DUMMY_SITE][DUMMY_USER]["expiry"]
    assert parse_expiry_date(exp) is not None


def test_cmd_add_key_with_expiry(tmp_vault: Path):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    ns = argparse.Namespace(
        vault=str(tmp_vault),
        site=DUMMY_SITE,
        username=DUMMY_USER,
        expiry="2030-01-15",
        no_expiry=False,
    )
    with patch("devsecret.cli.read_master_password", return_value=DUMMY_PASSWORD):
        with patch("getpass.getpass", return_value=DUMMY_API_KEY):
            cli.cmd_add_key(ns)
    data = load(tmp_vault, DUMMY_PASSWORD)
    assert data["api_keys"][DUMMY_SITE][DUMMY_USER]["expiry"] == "2030-01-15"


def test_cmd_add_key_no_expiry(tmp_vault: Path):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    ns = argparse.Namespace(
        vault=str(tmp_vault),
        site=DUMMY_SITE,
        username=DUMMY_USER,
        expiry=None,
        no_expiry=True,
    )
    with patch("devsecret.cli.read_master_password", return_value=DUMMY_PASSWORD):
        with patch("getpass.getpass", return_value=DUMMY_API_KEY):
            cli.cmd_add_key(ns)
    data = load(tmp_vault, DUMMY_PASSWORD)
    assert data["api_keys"][DUMMY_SITE][DUMMY_USER]["expiry"] == ""


def test_cmd_add_key_vault_missing_exits(tmp_path: Path):
    missing = tmp_path / "nope.enc"
    ns = argparse.Namespace(
        vault=str(missing),
        site=DUMMY_SITE,
        username=DUMMY_USER,
        expiry=None,
        no_expiry=False,
    )
    with pytest.raises(SystemExit) as exc:
        cli.cmd_add_key(ns)
    assert exc.value.code == 1


def test_cmd_add_key_empty_api_key_exits(tmp_vault: Path):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    ns = argparse.Namespace(
        vault=str(tmp_vault),
        site=DUMMY_SITE,
        username=DUMMY_USER,
        expiry=None,
        no_expiry=True,
    )
    with patch("devsecret.cli.read_master_password", return_value=DUMMY_PASSWORD):
        with patch("getpass.getpass", return_value=""):
            with pytest.raises(SystemExit) as exc:
                cli.cmd_add_key(ns)
    assert exc.value.code == 1


def test_cmd_add_key_load_crypto_error_exits(tmp_vault: Path):
    save(tmp_vault, "other-password", dict(EMPTY_VAULT))
    ns = argparse.Namespace(
        vault=str(tmp_vault),
        site=DUMMY_SITE,
        username=DUMMY_USER,
        expiry=None,
        no_expiry=True,
    )
    with patch("devsecret.cli.read_master_password", return_value=DUMMY_PASSWORD):
        with patch("getpass.getpass", return_value=DUMMY_API_KEY):
            with pytest.raises(SystemExit) as exc:
                cli.cmd_add_key(ns)
    assert exc.value.code == 1


def test_cmd_add_recovery_happy(tmp_vault: Path):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    ns = argparse.Namespace(
        vault=str(tmp_vault),
        site=DUMMY_SITE,
        username=DUMMY_USER,
        codes=["a", "b"],
    )
    with patch("devsecret.cli.read_master_password", return_value=DUMMY_PASSWORD):
        cli.cmd_add_recovery(ns)
    data = load(tmp_vault, DUMMY_PASSWORD)
    assert data["recovery_codes"][DUMMY_SITE][DUMMY_USER] == ["a", "b"]


def test_cmd_add_recovery_vault_missing_exits(tmp_path: Path):
    ns = argparse.Namespace(
        vault=str(tmp_path / "missing.enc"),
        site=DUMMY_SITE,
        username=DUMMY_USER,
        codes=["x"],
    )
    with pytest.raises(SystemExit) as exc:
        cli.cmd_add_recovery(ns)
    assert exc.value.code == 1


def test_cli_list_keys_respects_auto_delete_index(tmp_vault: Path, capsys):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    data = load(tmp_vault, DUMMY_PASSWORD)
    data["settings"]["auto_delete_expired_api_keys"] = True
    data["api_keys"][DUMMY_SITE] = {
        "gone": {"api_key": "x", "expiry": (utc_today() - timedelta(days=1)).isoformat()},
        "stay": {"api_key": "y", "expiry": (utc_today() + timedelta(days=30)).isoformat()},
    }
    save(tmp_vault, DUMMY_PASSWORD, data)

    cli.cmd_list_keys(argparse.Namespace(vault=str(tmp_vault)))
    out = capsys.readouterr().out
    assert "gone" not in out
    assert "stay" in out


def test_cmd_list_keys_vault_missing_exits(tmp_path: Path):
    with pytest.raises(SystemExit) as exc:
        cli.cmd_list_keys(argparse.Namespace(vault=str(tmp_path / "x.enc")))
    assert exc.value.code == 1


def test_cmd_list_keys_index_error_exits(tmp_vault: Path):
    tmp_vault.write_bytes(b"x")
    with pytest.raises(SystemExit) as exc:
        cli.cmd_list_keys(argparse.Namespace(vault=str(tmp_vault)))
    assert exc.value.code == 1


def test_cmd_list_recovery_happy(tmp_vault: Path, capsys):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    data = load(tmp_vault, DUMMY_PASSWORD)
    data["recovery_codes"][DUMMY_SITE] = {DUMMY_USER: list(DUMMY_RECOVERY)}
    save(tmp_vault, DUMMY_PASSWORD, data)
    with patch("devsecret.cli.read_master_password", return_value=DUMMY_PASSWORD):
        cli.cmd_list_recovery(argparse.Namespace(vault=str(tmp_vault)))
    out = capsys.readouterr().out
    assert DUMMY_SITE in out and DUMMY_USER in out


def test_cmd_list_recovery_vault_missing_exits(tmp_path: Path):
    with patch("devsecret.cli.read_master_password", return_value=DUMMY_PASSWORD):
        with pytest.raises(SystemExit) as exc:
            cli.cmd_list_recovery(argparse.Namespace(vault=str(tmp_path / "x.enc")))
    assert exc.value.code == 1


def test_cmd_get_key_happy(tmp_vault: Path, capsys):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    data = load(tmp_vault, DUMMY_PASSWORD)
    data["api_keys"][DUMMY_SITE] = {
        DUMMY_USER: {"api_key": DUMMY_API_KEY, "expiry": "2099-12-31"},
    }
    save(tmp_vault, DUMMY_PASSWORD, data)
    with patch("devsecret.cli.read_master_password", return_value=DUMMY_PASSWORD):
        cli.cmd_get_key(
            argparse.Namespace(vault=str(tmp_vault), site=DUMMY_SITE, username=DUMMY_USER)
        )
    captured = capsys.readouterr()
    assert captured.out.strip() == DUMMY_API_KEY
    assert "expiry" in captured.err


def test_cmd_get_key_missing_entry_exits(tmp_vault: Path):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    with patch("devsecret.cli.read_master_password", return_value=DUMMY_PASSWORD):
        with pytest.raises(SystemExit) as exc:
            cli.cmd_get_key(
                argparse.Namespace(
                    vault=str(tmp_vault), site=DUMMY_SITE, username="nobody"
                )
            )
    assert exc.value.code == 1


def test_cmd_get_recovery_happy(tmp_vault: Path, capsys):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    data = load(tmp_vault, DUMMY_PASSWORD)
    data["recovery_codes"][DUMMY_SITE] = {DUMMY_USER: ["c1", "c2"]}
    save(tmp_vault, DUMMY_PASSWORD, data)
    with patch("devsecret.cli.read_master_password", return_value=DUMMY_PASSWORD):
        cli.cmd_get_recovery(
            argparse.Namespace(vault=str(tmp_vault), site=DUMMY_SITE, username=DUMMY_USER)
        )
    lines = capsys.readouterr().out.strip().splitlines()
    assert lines == ["c1", "c2"]


def test_cmd_get_recovery_missing_exits(tmp_vault: Path):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    with patch("devsecret.cli.read_master_password", return_value=DUMMY_PASSWORD):
        with pytest.raises(SystemExit) as exc:
            cli.cmd_get_recovery(
                argparse.Namespace(
                    vault=str(tmp_vault), site=DUMMY_SITE, username="nope"
                )
            )
    assert exc.value.code == 1


def test_cmd_configure_toggles_auto_delete(tmp_vault: Path):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    with patch("devsecret.cli.read_master_password", return_value=DUMMY_PASSWORD):
        cli.cmd_configure(
            argparse.Namespace(
                vault=str(tmp_vault),
                auto_delete_expired_api_keys=True,
            )
        )
    data = load(tmp_vault, DUMMY_PASSWORD)
    assert data["settings"]["auto_delete_expired_api_keys"] is True

    with patch("devsecret.cli.read_master_password", return_value=DUMMY_PASSWORD):
        cli.cmd_configure(
            argparse.Namespace(
                vault=str(tmp_vault),
                auto_delete_expired_api_keys=False,
            )
        )
    data = load(tmp_vault, DUMMY_PASSWORD)
    assert data["settings"]["auto_delete_expired_api_keys"] is False


def test_cmd_configure_save_oserror_exits(tmp_vault: Path):
    save(tmp_vault, DUMMY_PASSWORD, dict(EMPTY_VAULT))
    with patch("devsecret.cli.read_master_password", return_value=DUMMY_PASSWORD):
        with patch("devsecret.cli.save", side_effect=OSError("disk full")):
            with pytest.raises(SystemExit) as exc:
                cli.cmd_configure(
                    argparse.Namespace(
                        vault=str(tmp_vault),
                        auto_delete_expired_api_keys=True,
                    )
                )
    assert exc.value.code == 1


def test_build_parser_dispatches_init(tmp_vault: Path):
    parser = cli.build_parser()
    with patch("devsecret.cli.read_master_password", return_value=DUMMY_PASSWORD):
        args = parser.parse_args(["--vault", str(tmp_vault), "init"])
        args.func(args)
    assert tmp_vault.is_file()


def test_main_invokes_subcommand(tmp_vault: Path):
    with patch("devsecret.cli.read_master_password", return_value=DUMMY_PASSWORD):
        with patch.object(cli.sys, "argv", ["devsecret", "--vault", str(tmp_vault), "init"]):
            cli.main()
    assert tmp_vault.is_file()
