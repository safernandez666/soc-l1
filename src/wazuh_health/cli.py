"""wazuh-health CLI: serve | once | report | doctor | migrate."""
from __future__ import annotations

import argparse
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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wazuh-health")
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
