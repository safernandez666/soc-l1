"""Tests del executor - dispatch correcto + manejo de errores sin LLM."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from src.agents.narrator import ProposedAction
from src.config import LdapConfig
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
