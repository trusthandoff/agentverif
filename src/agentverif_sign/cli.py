"""Click CLI entry point for agentverif-sign."""

from __future__ import annotations

import logging
import sys

import click

from agentverif_sign.config import Config

logger = logging.getLogger(__name__)


@click.group()
@click.version_option(package_name="agentverif-sign")
@click.option("--debug", is_flag=True, help="Enable debug logging")
def main(debug: bool) -> None:
    """agentverif-sign — sign and verify AI agent packages."""
    level = logging.DEBUG if debug else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


# ---------------------------------------------------------------------------
# sign
# ---------------------------------------------------------------------------


@main.command("sign")
@click.argument("zip_path", metavar="ZIP")
@click.option(
    "--tier",
    type=click.Choice(["indie", "pro", "enterprise"]),
    default="indie",
    show_default=True,
    help="Signing tier",
)
@click.option("--api-key", envvar="AGENTVERIF_API_KEY", default=None, help="API key")
@click.option("--offline", is_flag=True, default=False, help="Skip registry")
def sign_cmd(zip_path: str, tier: str, api_key: str | None, offline: bool) -> None:
    """Sign an agent ZIP package."""
    from agentverif_sign import client as registry_client
    from agentverif_sign import scanner, signer

    cfg = Config.from_env(api_key=api_key)
    offline = offline or cfg.offline

    # Step 1 — validate
    try:
        signer.validate_zip(zip_path)
    except ValueError as exc:
        click.echo(f"\u274c {exc}", err=True)
        sys.exit(1)

    # Step 2 — scan
    click.echo("Scanning package...")
    try:
        scan_result = scanner.scan_zip(zip_path, cfg.scan_url)
    except RuntimeError as exc:
        click.echo(f"\u274c Scan error: {exc}", err=True)
        sys.exit(1)

    if not scan_result.passed:
        click.echo(f"\u274c Scan failed (score={scan_result.score}/100):", err=True)
        for v in scan_result.violations:
            click.echo(f"  - {v.get('rule', v)}", err=True)
        click.echo("Signing refused. Fix violations and try again.", err=True)
        sys.exit(1)

    # Step 3 — build signature record
    record = signer.sign_zip(zip_path, tier=tier, api_key=api_key, scan_result=scan_result)

    # Step 4 — register (optional)
    if not offline:
        try:
            registered_id = registry_client.register(record, cfg.sign_url, api_key=cfg.api_key)
            # Update license_id if registry assigned one
            from dataclasses import replace

            record = replace(record, license_id=registered_id)
        except Exception as exc:
            logger.warning("Registry unavailable, proceeding locally: %s", exc)
            click.echo("\u26a0 Registry unavailable — signed locally only", err=True)

    # Step 5 — inject
    signer.inject_signature(zip_path, record)

    # Step 6 — output
    from agentverif_sign.badges import render_badge

    badge = render_badge(record.tier, record.license_id)
    click.echo("\u2705 Signed successfully")
    click.echo(f"License: {record.license_id}")
    click.echo(f"Tier:    {record.tier}")
    click.echo(f"Hash:    {record.zip_hash}")
    click.echo(f"\nEmbed badge:\n{badge}")
    click.echo(f"\nVerify at: https://verify.agentverif.com/{record.license_id}")


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


@main.command("verify")
@click.argument("zip_path", metavar="ZIP")
@click.option("--offline", is_flag=True, default=False, help="Skip registry check")
@click.option("--json", "output_json", is_flag=True, default=False, help="JSON output")
def verify_cmd(zip_path: str, offline: bool, output_json: bool) -> None:
    """Verify a signed agent ZIP package."""
    from agentverif_sign import verifier

    cfg = Config.from_env()
    offline = offline or cfg.offline

    result = verifier.verify_zip(zip_path, offline=offline, sign_url=cfg.sign_url)

    if output_json:
        click.echo(result.to_json())
        sys.exit(0 if result.status in ("VERIFIED", "UNREGISTERED") else 1)

    status_icons = {
        "VERIFIED": "\u2705",
        "UNREGISTERED": "\u26a0",
        "MODIFIED": "\u26a0",
        "REVOKED": "\u274c",
        "UNSIGNED": "\u274c",
    }
    icon = status_icons.get(result.status, "?")
    click.echo(f"{icon} {result.status} — {result.message}")
    if result.badge:
        click.echo(f"\n{result.badge}")
    if result.verify_url:
        click.echo(f"\nVerify online: {result.verify_url}")

    sys.exit(0 if result.status in ("VERIFIED", "UNREGISTERED") else 1)


# ---------------------------------------------------------------------------
# revoke
# ---------------------------------------------------------------------------


@main.command("revoke")
@click.argument("license_id")
@click.option("--api-key", envvar="AGENTVERIF_API_KEY", required=True, help="API key")
def revoke_cmd(license_id: str, api_key: str) -> None:
    """Revoke a license ID."""
    from agentverif_sign import client as registry_client

    cfg = Config.from_env(api_key=api_key)
    try:
        registry_client.revoke(license_id, cfg.api_key, cfg.sign_url)  # type: ignore[arg-type]
        click.echo(f"\u2705 License {license_id} revoked successfully")
    except Exception as exc:
        click.echo(f"\u274c Revocation failed: {exc}", err=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# badge
# ---------------------------------------------------------------------------


@main.command("badge")
@click.argument("license_id")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "html", "markdown", "svg"]),
    default="text",
    show_default=True,
)
@click.option(
    "--tier",
    type=click.Choice(["indie", "pro", "enterprise"]),
    default="pro",
    show_default=True,
)
@click.option("--expires-at", default=None, help="Expiry date (ISO format)")
def badge_cmd(license_id: str, fmt: str, tier: str, expires_at: str | None) -> None:
    """Print the badge for a license ID."""
    from agentverif_sign.badges import render_badge

    badge = render_badge(tier, license_id=license_id, expires_at=expires_at, fmt=fmt)
    click.echo(badge)
