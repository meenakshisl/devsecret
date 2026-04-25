"""DevSecret CLI."""

from __future__ import annotations

import argparse
import getpass
import os
import shlex
import sys
from pathlib import Path

from devsecret.crypto import VaultCryptoError
from devsecret.vault import (
    API_KEY_EXPIRY_WARN_DAYS,
    DEFAULT_API_KEY_EXPIRY_DAYS,
    EMPTY_VAULT,
    default_api_key_expiry_string,
    load,
    parse_expiry_date,
    prune_expired_api_keys,
    read_api_key_index,
    save,
    utc_today,
)


def resolve_vault_path(vault_arg: str | None) -> Path:
    if vault_arg:
        return Path(vault_arg).expanduser()
    env = os.environ.get("DEVSECRET_VAULT")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".devsecret" / "vault.enc"


def exit_vault_missing(path: Path) -> None:
    print(f"Error: vault not found: {path}", file=sys.stderr)
    print(
        "Create it first, e.g. "
        f"devsecret init --vault {shlex.quote(str(path))}",
        file=sys.stderr,
    )
    sys.exit(1)


def read_master_password() -> str:
    pw = getpass.getpass("Master password: ")
    if not pw:
        print("Error: master password cannot be empty.", file=sys.stderr)
        sys.exit(1)
    return pw


def load_vault_maybe_prune(path: Path, password: str) -> dict:
    data = load(path, password)
    n = prune_expired_api_keys(data)
    if n > 0:
        save(path, password, data)
    return data


def warn_api_key_expiry(site: str, username: str, expiry_str: str) -> None:
    """Stderr warnings for a single API key expiry (recovery codes: N/A)."""
    exp = parse_expiry_date(expiry_str)
    if exp is None:
        return
    today = utc_today()
    days = (exp - today).days
    if days < 0:
        print(
            f"Warning: API key for {site}/{username} expired on {exp.isoformat()}.",
            file=sys.stderr,
        )
    elif days == 0:
        print(
            f"Warning: API key for {site}/{username} expires today ({exp.isoformat()}).",
            file=sys.stderr,
        )
    elif days <= API_KEY_EXPIRY_WARN_DAYS:
        print(
            f"Warning: API key for {site}/{username} expires on {exp.isoformat()} "
            f"({days} day(s) left).",
            file=sys.stderr,
        )


def collect_recovery_codes(codes_args: list[str] | None) -> list[str]:
    parts: list[str] = []
    if codes_args:
        for c in codes_args:
            for piece in c.split(","):
                piece = piece.strip()
                if piece:
                    parts.append(piece)
        return parts
    if sys.stdin.isatty():
        print("Enter recovery codes, one per line. Empty line to finish:", file=sys.stderr)
        while True:
            try:
                line = input().strip()
            except EOFError:
                break
            if not line:
                break
            parts.append(line)
    else:
        for line in sys.stdin:
            line = line.strip()
            if line:
                parts.append(line)
    if not parts:
        print("Error: no recovery codes provided.", file=sys.stderr)
        sys.exit(1)
    return parts


def cmd_init(args: argparse.Namespace) -> None:
    path = resolve_vault_path(args.vault)
    if path.exists() and not args.force:
        print(f"Error: vault already exists: {path}", file=sys.stderr)
        print("Use --force to overwrite.", file=sys.stderr)
        sys.exit(1)
    password = read_master_password()
    try:
        save(path, password, dict(EMPTY_VAULT))
    except OSError as e:
        print(f"Error: could not write vault: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"Initialized vault at {path}")


def cmd_add_key(args: argparse.Namespace) -> None:
    path = resolve_vault_path(args.vault)
    if not path.is_file():
        exit_vault_missing(path)
    password = read_master_password()
    api_key = getpass.getpass("API key: ")
    if not api_key:
        print("Error: API key cannot be empty.", file=sys.stderr)
        sys.exit(1)

    if args.no_expiry:
        expiry = ""
    elif args.expiry is not None:
        expiry = args.expiry
    else:
        expiry = default_api_key_expiry_string()
        print(
            f"Warning: no --expiry given; using default expiry of {DEFAULT_API_KEY_EXPIRY_DAYS} days "
            f"({expiry}). Use --expiry DATE or --no-expiry to change this.",
            file=sys.stderr,
        )

    try:
        data = load_vault_maybe_prune(path, password)
    except VaultCryptoError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    site = args.site
    user = args.username
    data["api_keys"].setdefault(site, {})
    data["api_keys"][site][user] = {
        "api_key": api_key,
        "expiry": expiry,
    }
    try:
        save(path, password, data)
    except OSError as e:
        print(f"Error: could not write vault: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"Stored API key for {site} / {user}")


def cmd_add_recovery(args: argparse.Namespace) -> None:
    path = resolve_vault_path(args.vault)
    if not path.is_file():
        exit_vault_missing(path)
    codes = collect_recovery_codes(args.codes)
    password = read_master_password()
    try:
        data = load_vault_maybe_prune(path, password)
    except VaultCryptoError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    site = args.site
    user = args.username
    data["recovery_codes"].setdefault(site, {})
    data["recovery_codes"][site][user] = codes
    try:
        save(path, password, data)
    except OSError as e:
        print(f"Error: could not write vault: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"Stored {len(codes)} recovery code(s) for {site} / {user}")


def cmd_list_keys(args: argparse.Namespace) -> None:
    path = resolve_vault_path(args.vault)
    if not path.is_file():
        exit_vault_missing(path)
    try:
        index = read_api_key_index(path)
    except VaultCryptoError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    today = utc_today()
    for site in sorted(index.api_keys.keys()):
        for username in sorted(index.api_keys[site].keys()):
            exp_str = index.api_keys[site][username]
            exp = parse_expiry_date(exp_str)
            if index.auto_delete_expired_api_keys and exp is not None and exp < today:
                continue
            print(f"{site}\t{username}")
            warn_api_key_expiry(site, username, exp_str)


def cmd_list_recovery(args: argparse.Namespace) -> None:
    path = resolve_vault_path(args.vault)
    if not path.is_file():
        exit_vault_missing(path)
    password = read_master_password()
    try:
        data = load_vault_maybe_prune(path, password)
    except VaultCryptoError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    for site in sorted(data["recovery_codes"].keys()):
        for username in sorted(data["recovery_codes"][site].keys()):
            print(f"{site}\t{username}")


def cmd_get_key(args: argparse.Namespace) -> None:
    path = resolve_vault_path(args.vault)
    if not path.is_file():
        exit_vault_missing(path)
    password = read_master_password()
    try:
        data = load_vault_maybe_prune(path, password)
    except VaultCryptoError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    site = args.site
    user = args.username
    try:
        entry = data["api_keys"][site][user]
    except KeyError:
        print(f"Error: no API key for {site} / {user}", file=sys.stderr)
        sys.exit(1)
    exp = entry.get("expiry") or ""
    warn_api_key_expiry(site, user, exp if isinstance(exp, str) else "")
    print(entry["api_key"])
    if exp:
        print(f"expiry: {exp}", file=sys.stderr)


def cmd_get_recovery(args: argparse.Namespace) -> None:
    path = resolve_vault_path(args.vault)
    if not path.is_file():
        exit_vault_missing(path)
    password = read_master_password()
    try:
        data = load_vault_maybe_prune(path, password)
    except VaultCryptoError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    site = args.site
    user = args.username
    try:
        codes = data["recovery_codes"][site][user]
    except KeyError:
        print(f"Error: no recovery codes for {site} / {user}", file=sys.stderr)
        sys.exit(1)
    for c in codes:
        print(c)


def cmd_configure(args: argparse.Namespace) -> None:
    path = resolve_vault_path(args.vault)
    if not path.is_file():
        exit_vault_missing(path)
    password = read_master_password()
    try:
        data = load(path, password)
    except VaultCryptoError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    data.setdefault("settings", dict(EMPTY_VAULT["settings"]))
    data["settings"]["auto_delete_expired_api_keys"] = bool(
        args.auto_delete_expired_api_keys
    )
    removed = prune_expired_api_keys(data)
    try:
        save(path, password, data)
    except OSError as e:
        print(f"Error: could not write vault: {e}", file=sys.stderr)
        sys.exit(1)
    state = (
        "enabled"
        if data["settings"]["auto_delete_expired_api_keys"]
        else "disabled"
    )
    print(f"auto_delete_expired_api_keys is now {state}.", file=sys.stderr)
    if removed:
        print(f"Removed {removed} expired API key entry/entries.", file=sys.stderr)


def _add_vault_argument(parser: argparse.ArgumentParser) -> None:
    """Repeatable --vault on subcommands; SUPPRESS avoids clobbering the root --vault."""
    parser.add_argument(
        "--vault",
        default=argparse.SUPPRESS,
        metavar="PATH",
        help="Vault file (default: ~/.devsecret/vault.enc or DEVSECRET_VAULT)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="devsecret",
        description="Secure API key and recovery code vault (encrypted).",
    )
    parser.add_argument(
        "--vault",
        default=None,
        metavar="PATH",
        help="Vault file (default: ~/.devsecret/vault.enc or DEVSECRET_VAULT)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="Create a new empty vault")
    _add_vault_argument(p)
    p.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing vault file",
    )
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("add-key", help="Store an API key")
    _add_vault_argument(p)
    p.add_argument("--site", required=True)
    p.add_argument("--username", required=True)
    ex = p.add_mutually_exclusive_group()
    ex.add_argument(
        "--expiry",
        default=None,
        metavar="DATE",
        help="Expiry as YYYY-MM-DD (default: 90 days from today if omitted)",
    )
    ex.add_argument(
        "--no-expiry",
        action="store_true",
        help="Store without an expiry date",
    )
    p.set_defaults(func=cmd_add_key)

    p = sub.add_parser("add-recovery", help="Store recovery codes (replaces existing)")
    _add_vault_argument(p)
    p.add_argument("--site", required=True)
    p.add_argument("--username", required=True)
    p.add_argument(
        "--codes",
        action="append",
        metavar="CODE",
        default=None,
        help="Code(s); repeat flag or use commas. If omitted, read stdin or prompt.",
    )
    p.set_defaults(func=cmd_add_recovery)

    p = sub.add_parser(
        "list-keys",
        help="List site/username for API keys (metadata only; uses plaintext sidecar index)",
    )
    _add_vault_argument(p)
    p.set_defaults(func=cmd_list_keys)

    p = sub.add_parser("list-recovery", help="List site/username for recovery codes")
    _add_vault_argument(p)
    p.set_defaults(func=cmd_list_recovery)

    p = sub.add_parser("get-key", help="Print API key (and expiry on stderr)")
    _add_vault_argument(p)
    p.add_argument("--site", required=True)
    p.add_argument("--username", required=True)
    p.set_defaults(func=cmd_get_key)

    p = sub.add_parser("get-recovery", help="Print recovery codes")
    _add_vault_argument(p)
    p.add_argument("--site", required=True)
    p.add_argument("--username", required=True)
    p.set_defaults(func=cmd_get_recovery)

    p = sub.add_parser(
        "configure",
        help="Vault options (API keys only): auto-delete expired keys after load/save",
    )
    _add_vault_argument(p)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument(
        "--enable-auto-delete-expired-api-keys",
        action="store_const",
        const=True,
        dest="auto_delete_expired_api_keys",
        help="Remove API keys past expiry when the vault is loaded (requires password)",
    )
    g.add_argument(
        "--disable-auto-delete-expired-api-keys",
        action="store_const",
        const=False,
        dest="auto_delete_expired_api_keys",
        help="Stop auto-removing expired API keys",
    )
    p.set_defaults(func=cmd_configure)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
