"""Tests del executor - dispatch correcto + manejo de errores sin LLM."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from src.agents.narrator import ProposedAction
from src.config import LdapConfig, Settings
from src.executor import execute_plan
from src.models import LdapActionResult


@pytest.fixture
def ldap_cfg() -> LdapConfig:
    return LdapConfig(
        host="ad.test",
        bind_dn="svc@test",
        bind_password="x",
        use_starttls=False,
        credentials_file="/nonexistent",
    )


@pytest.mark.asyncio
async def test_notify_only_is_noop_and_ok() -> None:
    actions = [ProposedAction(type="notify_only", target="jdoe", justification="x")]
    results = await execute_plan(actions, ldap_cfg=None)
    assert len(results) == 1
    assert results[0]["ok"] is True
    assert results[0]["action_type"] == "notify_only"


@pytest.mark.asyncio
async def test_escalate_l2_logs_warning_returns_ok(caplog) -> None:
    actions = [
        ProposedAction(
            type="escalate_l2",
            target="incident-xyz",
            justification="MITRE T1059 - revisar L2",
        )
    ]
    with caplog.at_level("WARNING", logger="soc-l1"):
        results = await execute_plan(actions, ldap_cfg=None)
    assert results[0]["ok"] is True
    assert any("ESCALATE_L2" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_disable_user_calls_ldap_tool(ldap_cfg) -> None:
    """Verifica que disable_user dispatchea a tools.ldap.disable_user con el sam correcto."""
    fake_result = LdapActionResult(
        ok=True,
        action="disable_user",
        target_sam="jdoe",
        target_dn="CN=jdoe,DC=test",
    )
    actions = [ProposedAction(type="disable_user", target="jdoe", justification="x")]
    with patch("src.executor.ldap_tools.disable_user", return_value=fake_result) as mock_fn:
        results = await execute_plan(actions, ldap_cfg=ldap_cfg)

    mock_fn.assert_called_once_with(ldap_cfg, "jdoe")
    assert results[0]["ok"] is True
    assert results[0]["target"] == "jdoe"
    assert "CN=jdoe" in results[0]["message"]


@pytest.mark.asyncio
async def test_force_password_change_calls_ldap_tool(ldap_cfg) -> None:
    fake_result = LdapActionResult(
        ok=True,
        action="force_password_change",
        target_sam="asmith",
        target_dn="CN=asmith,DC=test",
    )
    actions = [
        ProposedAction(type="force_password_change", target="asmith", justification="x")
    ]
    with patch(
        "src.executor.ldap_tools.force_password_change", return_value=fake_result
    ) as mock_fn:
        results = await execute_plan(actions, ldap_cfg=ldap_cfg)
    mock_fn.assert_called_once_with(ldap_cfg, "asmith")
    assert results[0]["ok"] is True


@pytest.mark.asyncio
async def test_ldap_action_without_config_fails_cleanly() -> None:
    """Si ldap_cfg=None, las acciones AD retornan ok=false (no crash)."""
    actions = [ProposedAction(type="disable_user", target="jdoe", justification="x")]
    results = await execute_plan(actions, ldap_cfg=None)
    assert results[0]["ok"] is False
    assert "LDAP no configurado" in results[0]["message"]


@pytest.mark.asyncio
async def test_ldap_exception_is_captured(ldap_cfg) -> None:
    """Excepciones del LDAP no rompen el dispatcher - se capturan en ExecutionResult."""
    actions = [ProposedAction(type="disable_user", target="jdoe", justification="x")]
    with patch("src.executor.ldap_tools.disable_user", side_effect=Exception("LDAP boom")):
        results = await execute_plan(actions, ldap_cfg=ldap_cfg)
    assert results[0]["ok"] is False
    assert "LDAP boom" in results[0]["message"]


@pytest.mark.asyncio
async def test_multiple_actions_run_sequentially(ldap_cfg) -> None:
    """Todas las actions se ejecutan, una falla no aborta el resto."""
    fake_ok = LdapActionResult(ok=True, action="disable_user", target_sam="jdoe")
    actions = [
        ProposedAction(type="disable_user", target="jdoe", justification="x"),
        ProposedAction(type="notify_only", target="alert-x", justification="x"),
        ProposedAction(type="force_password_change", target="asmith", justification="x"),
    ]
    fake_force = LdapActionResult(
        ok=False,
        action="force_password_change",
        target_sam="asmith",
        message="permission denied",
    )
    with patch("src.executor.ldap_tools.disable_user", return_value=fake_ok), patch(
        "src.executor.ldap_tools.force_password_change", return_value=fake_force
    ):
        results = await execute_plan(actions, ldap_cfg=ldap_cfg)

    assert len(results) == 3
    assert results[0]["ok"] is True   # disable
    assert results[1]["ok"] is True   # notify
    assert results[2]["ok"] is False  # force_password failed
    assert "permission denied" in results[2]["message"]


@pytest.mark.asyncio
async def test_empty_plan_returns_empty_list() -> None:
    results = await execute_plan([], ldap_cfg=None)
    assert results == []


# ===== Guardrails: PROTECTED_USERS + DRY_RUN_MODE =====


@pytest.mark.asyncio
async def test_protected_user_refuses_disable(ldap_cfg) -> None:
    """Si el target está en PROTECTED_USERS, executor refusa sin tocar AD."""
    settings = Settings(
        openai_api_key="x", protected_users="jdoe,admin"
    )
    actions = [
        ProposedAction(type="disable_user", target="jdoe", justification="x"),
    ]
    with patch("src.executor.ldap_tools.disable_user") as mock_fn:
        results = await execute_plan(actions, ldap_cfg=ldap_cfg, settings=settings)

    mock_fn.assert_not_called()  # Critical: LDAP nunca se invocó
    assert results[0]["ok"] is False
    assert "PROTECTED_USERS" in results[0]["message"]
    assert "jdoe" in results[0]["message"]


@pytest.mark.asyncio
async def test_protected_user_match_is_case_insensitive(ldap_cfg) -> None:
    """PROTECTED_USERS=admin debe matchear ADMIN, Admin, etc."""
    settings = Settings(openai_api_key="x", protected_users="ADMIN")
    actions = [
        ProposedAction(type="disable_user", target="admin", justification="x"),
        ProposedAction(type="force_password_change", target="Admin", justification="x"),
    ]
    with patch("src.executor.ldap_tools.disable_user") as mock_disable, patch(
        "src.executor.ldap_tools.force_password_change"
    ) as mock_force:
        results = await execute_plan(actions, ldap_cfg=ldap_cfg, settings=settings)

    mock_disable.assert_not_called()
    mock_force.assert_not_called()
    assert all(r["ok"] is False for r in results)
    assert all("PROTECTED_USERS" in r["message"] for r in results)


@pytest.mark.asyncio
async def test_non_protected_user_proceeds(ldap_cfg) -> None:
    """Users que no están en PROTECTED_USERS pasan normal."""
    settings = Settings(openai_api_key="x", protected_users="admin")
    fake_ok = LdapActionResult(ok=True, action="disable_user", target_sam="jdoe")
    actions = [
        ProposedAction(type="disable_user", target="jdoe", justification="x"),
    ]
    with patch("src.executor.ldap_tools.disable_user", return_value=fake_ok) as mock_fn:
        results = await execute_plan(actions, ldap_cfg=ldap_cfg, settings=settings)

    mock_fn.assert_called_once_with(ldap_cfg, "jdoe")
    assert results[0]["ok"] is True


@pytest.mark.asyncio
async def test_dry_run_mode_simulates_without_ad_calls(ldap_cfg) -> None:
    """DRY_RUN=true convierte acciones AD en no-op (logueadas pero no ejecutadas)."""
    settings = Settings(openai_api_key="x", dry_run_mode=True)
    actions = [
        ProposedAction(type="disable_user", target="jdoe", justification="x"),
        ProposedAction(type="force_password_change", target="asmith", justification="x"),
    ]
    with patch("src.executor.ldap_tools.disable_user") as mock_disable, patch(
        "src.executor.ldap_tools.force_password_change"
    ) as mock_force:
        results = await execute_plan(actions, ldap_cfg=ldap_cfg, settings=settings)

    mock_disable.assert_not_called()
    mock_force.assert_not_called()
    assert all(r["ok"] is True for r in results)
    assert all("DRY_RUN" in r["message"] for r in results)


@pytest.mark.asyncio
async def test_notify_and_escalate_unaffected_by_dry_run() -> None:
    """notify_only y escalate_l2 son siempre no-op, dry_run no las cambia."""
    settings = Settings(openai_api_key="x", dry_run_mode=True)
    actions = [
        ProposedAction(type="notify_only", target="x", justification="x"),
        ProposedAction(type="escalate_l2", target="incident-1", justification="x"),
    ]
    results = await execute_plan(actions, ldap_cfg=None, settings=settings)
    assert results[0]["ok"] is True
    assert "noted" in results[0]["message"]
    assert results[1]["ok"] is True
    assert "escalated" in results[1]["message"]


@pytest.mark.asyncio
async def test_protected_users_set_parsing() -> None:
    """Settings.protected_users_set() ignora vacíos y normaliza."""
    s = Settings(openai_api_key="x", protected_users="  Admin , , jdoe, ")
    assert s.protected_users_set() == {"admin", "jdoe"}


@pytest.mark.asyncio
async def test_empty_protected_users_means_no_protection() -> None:
    """Sin PROTECTED_USERS configurado, executor opera normal."""
    settings = Settings(openai_api_key="x", protected_users="")
    fake_ok = LdapActionResult(ok=True, action="disable_user", target_sam="anyone")
    actions = [ProposedAction(type="disable_user", target="anyone", justification="x")]
    with patch("src.executor.ldap_tools.disable_user", return_value=fake_ok) as mock_fn:
        await execute_plan(actions, ldap_cfg=LdapConfig(
            host="ad.test", bind_dn="x@y", bind_password="z",
            use_starttls=False, credentials_file="/nope",
        ), settings=settings)
    mock_fn.assert_called_once()


# ===== block_ip + PROTECTED_NETWORKS =====


@pytest.mark.asyncio
async def test_block_ip_refused_for_protected_network() -> None:
    """RFC1918 (10.0.0.0/8) está en default PROTECTED_NETWORKS → refused."""
    settings = Settings(
        openai_api_key="x",
        fortigate_host="fg.test", fortigate_token="t",
        # protected_networks usa default que incluye 10.0.0.0/8
    )
    actions = [ProposedAction(type="block_ip", target="10.99.0.42", justification="x")]
    with patch("src.executor._exec_block_ip") as mock_fn:
        results = await execute_plan(actions, ldap_cfg=None, settings=settings)
    mock_fn.assert_not_called()
    assert results[0]["ok"] is False
    assert "PROTECTED_NETWORKS" in results[0]["message"]
    assert "10.0.0.0/8" in results[0]["message"]


@pytest.mark.asyncio
async def test_block_ip_refused_for_invalid_ip() -> None:
    settings = Settings(
        openai_api_key="x", fortigate_host="fg.test", fortigate_token="t",
    )
    actions = [ProposedAction(type="block_ip", target="not-an-ip", justification="x")]
    results = await execute_plan(actions, ldap_cfg=None, settings=settings)
    assert results[0]["ok"] is False
    assert "no es una IP válida" in results[0]["message"]


@pytest.mark.asyncio
async def test_block_ip_dry_run_no_op() -> None:
    """Con DRY_RUN_MODE=true, block_ip no toca FortiGate."""
    settings = Settings(
        openai_api_key="x",
        fortigate_host="fg.test", fortigate_token="t",
        dry_run_mode=True,
        protected_networks="",  # vacío para que la IP pase el guardrail
    )
    actions = [ProposedAction(type="block_ip", target="1.2.3.4", justification="x")]
    with patch("src.executor._exec_block_ip") as mock_fn:
        results = await execute_plan(actions, ldap_cfg=None, settings=settings)
    mock_fn.assert_not_called()
    assert results[0]["ok"] is True
    assert "DRY_RUN" in results[0]["message"]


@pytest.mark.asyncio
async def test_block_ip_executes_on_public_ip_when_not_dry_run() -> None:
    """IP pública (no RFC1918), no dry_run, FortiGate configurado → ejecuta."""
    from src.models import FortigateActionResult
    settings = Settings(
        openai_api_key="x",
        fortigate_host="fg.test", fortigate_token="t",
        dry_run_mode=False,
        protected_networks="",
    )
    actions = [ProposedAction(type="block_ip", target="203.0.113.45", justification="x")]
    fake_result = FortigateActionResult(
        ok=True, ip="203.0.113.45", action="quarantine_ip",
        expires_at="2026-05-17T11:00:00+00:00", message="banned for 3600s",
    )
    with patch("src.executor._exec_block_ip", new_callable=AsyncMock) as mock_fn:
        from src.executor import ExecutionResult
        mock_fn.return_value = ExecutionResult(
            action_type="block_ip", target="203.0.113.45", ok=True,
            message="banned for 3600s",
        )
        results = await execute_plan(actions, ldap_cfg=None, settings=settings)
    mock_fn.assert_called_once()
    assert results[0]["ok"] is True


@pytest.mark.asyncio
async def test_block_ip_without_fortigate_config_fails() -> None:
    """Sin FORTIGATE_HOST/TOKEN, block_ip retorna ok=False."""
    settings = Settings(
        openai_api_key="x", fortigate_host="", fortigate_token="",
        protected_networks="",
    )
    actions = [ProposedAction(type="block_ip", target="1.2.3.4", justification="x")]
    results = await execute_plan(actions, ldap_cfg=None, settings=settings)
    assert results[0]["ok"] is False
    assert "FortiGate no configurado" in results[0]["message"]


# ===== scan_host / isolate_host + PROTECTED_HOSTS =====


def _defender_settings(**kw) -> Settings:
    base = dict(
        openai_api_key="x",
        defender_tenant_id="t", defender_client_id="ci", defender_client_secret="cs",
    )
    base.update(kw)
    return Settings(**base)


@pytest.mark.asyncio
async def test_protected_host_refuses_isolate() -> None:
    """Host en PROTECTED_HOSTS → executor refusa sin tocar Defender."""
    settings = _defender_settings(protected_hosts="dc01,exchange01")
    actions = [ProposedAction(type="isolate_host", target="DC01", justification="x")]
    with patch("src.executor._exec_defender_action") as mock_fn:
        results = await execute_plan(actions, ldap_cfg=None, settings=settings)
    mock_fn.assert_not_called()
    assert results[0]["ok"] is False
    assert "PROTECTED_HOSTS" in results[0]["message"]


@pytest.mark.asyncio
async def test_scan_host_dry_run_no_op() -> None:
    """DRY_RUN=true → scan_host no llama a Defender."""
    settings = _defender_settings(dry_run_mode=True)
    actions = [ProposedAction(type="scan_host", target="goanote2109", justification="x")]
    with patch("src.executor._exec_defender_action") as mock_fn:
        results = await execute_plan(actions, ldap_cfg=None, settings=settings)
    mock_fn.assert_not_called()
    assert results[0]["ok"] is True
    assert "DRY_RUN" in results[0]["message"]


@pytest.mark.asyncio
async def test_scan_host_without_defender_config_fails() -> None:
    """Sin credenciales MDE → ok=False, no crash."""
    settings = Settings(openai_api_key="x")  # defender_* vacíos
    actions = [ProposedAction(type="scan_host", target="goanote2109", justification="x")]
    results = await execute_plan(actions, ldap_cfg=None, settings=settings)
    assert results[0]["ok"] is False
    assert "Defender (MDE) no configurado" in results[0]["message"]


@pytest.mark.asyncio
async def test_isolate_host_executes_when_configured() -> None:
    """Configurado + no dry_run + host no protegido → dispatchea a _exec_defender_action."""
    settings = _defender_settings(dry_run_mode=False, protected_hosts="")
    actions = [ProposedAction(type="isolate_host", target="pwned01", justification="x")]
    with patch("src.executor._exec_defender_action", new_callable=AsyncMock) as mock_fn:
        from src.executor import ExecutionResult
        mock_fn.return_value = ExecutionResult(
            action_type="isolate_host", target="pwned01", ok=True, message="isolated",
        )
        results = await execute_plan(actions, ldap_cfg=None, settings=settings)
    mock_fn.assert_called_once()
    assert results[0]["ok"] is True
