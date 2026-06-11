"""Generate conservative Wazuh hygiene recommendations."""
from __future__ import annotations

import html
import re

from src.cleanswarm.models import NoiseBucket, Recommendation


def _safe_id(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", value).strip("-")[:80]


def _condition_xml(condition: dict[str, str]) -> str:
    lines: list[str] = []
    if agent_name := condition.get("agent.name"):
        lines.append(f"    <field name=\"agent.name\">^{html.escape(agent_name)}$</field>")
    if srcip := condition.get("srcip"):
        lines.append(f"    <srcip>{html.escape(srcip)}</srcip>")
    if user := condition.get("user"):
        lines.append(f"    <field name=\"data.srcuser\">^{html.escape(user)}$</field>")
    return "\n".join(lines)


def _proposed_local_rule(bucket: NoiseBucket, local_rule_id: int) -> str:
    condition = {k: v for k, v in bucket.dimensions.items() if k != "rule_id"}
    conditions = _condition_xml(condition)
    comment = html.escape(f"CleanSwarm candidate for noisy rule {bucket.rule_id}; review before enabling")
    description = html.escape(f"CleanSwarm suppress noisy {bucket.rule_id} conditionally")
    return f"""<!-- {comment} -->
<rule id=\"{local_rule_id}\" level=\"0\">
    <if_sid>{html.escape(str(bucket.rule_id))}</if_sid>
{conditions}
    <description>{description}</description>
</rule>"""


def recommend_from_buckets(
    buckets: list[NoiseBucket],
    *,
    total_alerts: int,
    max_recommendations: int = 10,
    first_local_rule_id: int = 110000,
) -> list[Recommendation]:
    recommendations: list[Recommendation] = []

    for idx, bucket in enumerate(buckets[:max_recommendations], start=0):
        if not bucket.rule_id:
            continue
        condition = {k: v for k, v in bucket.dimensions.items() if k != "rule_id"}
        ratio = bucket.count / max(total_alerts, 1)

        if bucket.rule_level >= 10:
            rec_type = "investigate_source"
            risk = "high"
            proposed_rule = None
            reason = (
                "Volumen alto, pero la severidad de la regla es alta. No conviene silenciar; "
                "primero revisar el origen o reemplazar por una correlación más precisa."
            )
        elif not condition:
            rec_type = "tune_frequency"
            risk = "medium"
            proposed_rule = None
            reason = (
                "La regla es ruidosa de forma global. Mejor ajustar frecuencia/threshold o crear "
                "una correlación antes que apagarla completa."
            )
        else:
            rec_type = "suppress_conditionally"
            risk = "low" if bucket.rule_level <= 5 and ratio <= 0.8 else "medium"
            proposed_rule = _proposed_local_rule(bucket, first_local_rule_id + idx)
            reason = (
                "Patrón repetido con dimensiones específicas. Candidato a supresión condicional "
                "reversible, no a desactivar la regla global."
            )

        recommendations.append(
            Recommendation(
                id=f"cs-{_safe_id(bucket.key)}",
                type=rec_type,
                title=f"Reducir ruido de regla {bucket.rule_id}: {bucket.rule_description[:80]}",
                rule_id=str(bucket.rule_id),
                condition=condition,
                reason=reason,
                risk=risk,
                expected_reduction_count=bucket.count,
                expected_reduction_ratio=round(ratio, 4),
                proposed_wazuh_rule=proposed_rule,
                rollback=(
                    "No aplicado automáticamente. Si se aprueba y se agrega al local_rules.xml, "
                    f"rollback = remover la regla CleanSwarm asociada a {bucket.rule_id}."
                ),
            )
        )

    return recommendations
