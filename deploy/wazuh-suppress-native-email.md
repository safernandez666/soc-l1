# Apagar el email nativo de Wazuh ("Unified Email Notifier v4.9") para alertas que ya notifica SOC L1

**Problema:** una misma alerta dispara DOS emails: el del integrator nativo de Wazuh
(`Unified Email Notifier v4.9`) y el de SOC L1 (`[SOC L1]...`). Queremos que **solo
SOC L1** notifique esas alertas.

**Dónde se arregla:** en el **Wazuh manager** (`seg-vs85-prod01`), NO en este repo.
El integrator nativo vive en `/var/ossec/etc/ossec.conf`. Editar requiere acceso al
manager y un `systemctl restart wazuh-manager`.

> ⚠️ Reemplazá los `rule_id` / `group` de ejemplo por los reales que dispara la
> alerta de "Information stealing malware activity" (rule de Defender→Wazuh que
> consume SOC L1). Para encontrarlos: `grep -i "information stealing" /var/ossec/logs/alerts/alerts.json`
> o miralos en el dashboard de Wazuh (campo `rule.id`).

## Caso A — es un `<integration>` con script de email (lo más probable por el branding "Unified...")

Buscá el bloque `<integration>` cuyo `<name>` apunta al mailer custom y **restringilo**
para que NO procese lo que SOC L1 ya cubre. La forma más limpia es invertir el filtro:
que el integrator nativo mande SOLO lo que SOC L1 *no* maneja.

```xml
<integration>
  <name>custom-unified-mailer</name>           <!-- ajustar al name real -->
  <!-- Sacá del alcance del mailer nativo las reglas/grupos que ya notifica SOC L1.
       Dejá acá SOLO los grupos que SOC L1 NO procesa: -->
  <group>syscheck,rootcheck</group>            <!-- ejemplo: ajustar -->
  <alert_format>json</alert_format>
</integration>
```

Si el integrator no soporta exclusión, otra opción es subir su `<level>` mínimo por
encima del de esas reglas, o filtrar por `<rule_id>` en el propio script.

## Caso B — es `<email_alerts>` granular (alertas por email del manager)

Excluí las reglas que SOC L1 ya notifica para que no generen email nativo:

```xml
<email_alerts>
  <email_to>soc@tuorg.com</email_to>
  <do_not_delay />
  <!-- Estas rules las notifica SOC L1: NO mandar email nativo por ellas -->
  <rule_id>100200,100201</rule_id>             <!-- ⚠ ajustar a los IDs reales -->
</email_alerts>
```

> Nota: `<email_alerts>` con `<rule_id>` define a qué reglas se les manda mail. Si tu
> config global tiene `<email_alert_level>` que captura estas reglas por nivel, vas a
> tener que mover esas reglas a su propio `<email_alerts>` o ajustar el nivel global.

## Aplicar

```bash
sudo vi /var/ossec/etc/ossec.conf      # editar el bloque correspondiente
sudo /var/ossec/bin/wazuh-control restart   # o: systemctl restart wazuh-manager
```

Validá que la próxima alerta de info-stealer llegue **solo** como `[SOC L1]...`.

---

**Pendiente para precisión:** pasar el bloque `<integration>` / `<email_alerts>` actual
del `ossec.conf` + los `rule.id` reales, y se completa el filtro exacto.
