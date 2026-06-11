"""wazuh-health CLI: serve | once | report | doctor | migrate."""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from src.wazuh_health.config.settings import HealthConfig, load_config
from src.wazuh_health.daemon import HealthDaemon
from src.wazuh_health.probes.capacity import CapacityProbe
from src.wazuh_health.probes.coverage import CoverageProbe
from src.wazuh_health.probes.hygiene import HygieneProbe
from src.wazuh_health.scheduler import Job, Scheduler
from src.wazuh_health.source.local_fs import LocalFSSource
from src.wazuh_health.source.wazuh_api import WazuhAPISource
from src.wazuh_health.store.audit_store import AuditStore
from src.wazuh_health.store.db import connect, migrate
from src.wazuh_health.store.findings_store import FindingsStore


def load_env_file(path: str | Path | None) -> Path | None:
    """Load environment variables from a .env file.

    Resolution order (first hit wins):
      1. Explicit `path` argument (from --env-file CLI flag)
      2. WAZUH_HEALTH_ENV_FILE env var
      3. ./.env in the current working directory

    Returns the path that was loaded, or None if nothing was found.
    Existing environment variables are NOT overwritten (override=False).
    """
    from dotenv import load_dotenv

    candidates: list[Path] = []
    if path:
        candidates.append(Path(path))
    if env_override := os.getenv("WAZUH_HEALTH_ENV_FILE"):
        candidates.append(Path(env_override))
    candidates.append(Path.cwd() / ".env")

    for candidate in candidates:
        if candidate.is_file():
            load_dotenv(candidate, override=False)
            return candidate
    return None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wazuh-health")
    p.add_argument(
        "--env-file",
        default=None,
        help="Path to a .env file (default: ./.env or $WAZUH_HEALTH_ENV_FILE)",
    )
    sub = p.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve")
    serve.add_argument("--port", type=int, default=8787)

    once = sub.add_parser("once")
    once.add_argument("--alerts-path", default=None)

    report = sub.add_parser("report")
    report.add_argument("--since", default="24h")
    report.add_argument("--out", default="")

    sub.add_parser("doctor")
    sub.add_parser("migrate")
    return p


def _build_email_notifier(cfg: HealthConfig):
    """Return an `EmailNotifier` if a recipient is configured, else None.

    Email is auto-enabled when `notify.email.to` is non-empty (which itself is
    sourced from `WAZUH_HEALTH_EMAIL_TO`). No need to set `notify.email.enabled`
    separately — having a recipient is the toggle.
    """
    if not cfg.notify.email.to:
        return None
    from src.wazuh_health.notify.email import EmailNotifier
    return EmailNotifier(
        to=cfg.notify.email.to,
        smtp_host=cfg.notify.email.smtp_host,
        smtp_port=cfg.notify.email.smtp_port,
        sender=cfg.notify.email.sender,
        smtp_user=cfg.notify.email.smtp_user or None,
        smtp_password=cfg.notify.email.smtp_password or None,
        use_tls=cfg.notify.email.use_tls,
    )


def _maybe_send_digest_email(cfg: HealthConfig, audit: AuditStore) -> bool:
    """Send a deterministic (no-LLM) digest if email is configured.

    Returns True if a mail was sent, False otherwise.
    """
    notifier = _build_email_notifier(cfg)
    if notifier is None:
        return False
    from src.wazuh_health.digest import build_email_digest
    subject, markdown = build_email_digest(audit)
    notifier.notify_digest(subject=subject, markdown=markdown)
    return True


def _make_source(cfg: HealthConfig, alerts_path_override: str | None = None):
    if cfg.source.backend == "wazuh_api":
        import os
        return WazuhAPISource(
            host=cfg.source.wazuh_api.host,
            port=cfg.source.wazuh_api.port,
            user=os.environ["WAZUH_API_USER"],
            password=os.environ["WAZUH_API_PASSWORD"],
            verify_ssl=cfg.source.wazuh_api.verify_ssl,
        )
    return LocalFSSource(
        alerts_path=Path(alerts_path_override or cfg.source.local_fs.alerts_path),
        rotated_glob=cfg.source.local_fs.rotated_glob,
        ossec_conf=Path(cfg.source.local_fs.ossec_conf),
        client_keys=Path(cfg.source.local_fs.client_keys),
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    load_env_file(args.env_file)
    cfg = load_config()

    if args.command == "migrate":
        conn = connect(cfg.storage.db_path); migrate(conn)
        print(f"Migrated: {cfg.storage.db_path}")
        return 0

    if args.command == "doctor":
        try:
            conn = connect(cfg.storage.db_path); migrate(conn)
            print("doctor: store ok")
            return 0
        except Exception as exc:
            print(f"doctor: FAILED — {exc}", file=sys.stderr)
            return 1

    if args.command == "once":
        conn = connect(cfg.storage.db_path); migrate(conn)
        audit = AuditStore(conn); store = FindingsStore(conn)
        src = _make_source(cfg, args.alerts_path)
        for probe in (CapacityProbe(source=src),
                      HygieneProbe(source=src),
                      CoverageProbe(source=src)):
            audit.record_probe_run(probe.run())
        if _maybe_send_digest_email(cfg, audit):
            print(f"email digest sent to {cfg.notify.email.to}")
        return 0

    if args.command == "report":
        from src.wazuh_health.agents.reporter import invoke_reporter_agent
        conn = connect(cfg.storage.db_path); migrate(conn)
        audit = AuditStore(conn); store = FindingsStore(conn)
        hours = int(args.since.rstrip("h")) if args.since.endswith("h") else 24
        report = invoke_reporter_agent(
            audit_store=audit, findings_store=store,
            heavy_model=cfg.llm.heavy_model, window_hours=hours,
            now=datetime.now(tz=timezone.utc),
        )
        out = report.model_dump_json(indent=2)
        if args.out:
            Path(args.out).write_text(out, encoding="utf-8")
        else:
            print(out)
        # Mail the LLM-generated report when email is configured.
        notifier = _build_email_notifier(cfg)
        if notifier is not None:
            notifier.notify_report(report, markdown=out)
            print(f"email report sent to {cfg.notify.email.to}", file=sys.stderr)
        return 0

    if args.command == "serve":
        conn = connect(cfg.storage.db_path); migrate(conn)
        audit = AuditStore(conn)
        src = _make_source(cfg)
        sched = Scheduler(jitter_seconds=cfg.scheduler.jitter_seconds)
        sched.add(Job(
            name="capacity",
            interval_seconds=cfg.scheduler.jobs["capacity"].interval_seconds,
            callback=lambda: audit.record_probe_run(CapacityProbe(source=src).run()),
        ))
        sched.add(Job(
            name="hygiene",
            interval_seconds=cfg.scheduler.jobs["hygiene"].interval_seconds,
            callback=lambda: audit.record_probe_run(HygieneProbe(source=src).run()),
        ))
        sched.add(Job(
            name="coverage",
            interval_seconds=cfg.scheduler.jobs["coverage"].interval_seconds,
            callback=lambda: audit.record_probe_run(CoverageProbe(source=src).run()),
        ))
        HealthDaemon(port=args.port).run_forever(sched)
        return 0

    return 2
