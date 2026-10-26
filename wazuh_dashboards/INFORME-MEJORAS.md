# Informe: Mejoras a dashboards de Wazuh — 2026-07-21

## Resumen

Se auditaron y mejoraron los 5 dashboards del Wazuh Dashboard (OpenSearch Dashboards 2.19.5)
contra los datos reales del indexer. Se importaron 64 saved objects (overwrite), quedando
backup del estado original en `original/export_all.ndjson`.

Para revertir todo: Stack Management → Saved Objects → Import → `original/export_all.ndjson`
con overwrite activado.

## Hallazgos de seguridad (acción recomendada)

1. **Regla DCSync (100123) dispara ~15.000 eventos/semana por la cuenta `MSOL_db1b455c8596`
   (Azure AD Connect)**: es un falso positivo masivo. Recomendado: tunear la regla 100123
   para excluir cuentas `MSOL_*` (o crear regla hija con nivel alto solo para cuentas
   NO-MSOL). Mientras tanto, el dashboard tiene el panel "AD - DCSync Real (sin MSOL)".
2. **Uso intensivo del usuario `sa` de SQL Server desde IPs remotas** (13.338 logons desde
   192.168.38.27, 4.323 desde 10.3.50.36, etc. en 7 días): mala práctica grave. Nuevo panel
   "SQL - Accesos con sa" lo visibiliza. Recomendado: migrar aplicaciones a cuentas de
   servicio y deshabilitar `sa` por red.
3. **El dashboard Kong no recibe datos** (0 eventos en 90 días, ni en alerts ni en archives):
   la integración Kong → Wazuh nunca llegó o dejó de enviar. Los 10 paneles originales están
   vacíos por esto, no por diseño. Se agregó un panel de aviso en el dashboard.
4. **NetSecOps está dominado por scanners benignos de Internet** (Masscan, ZGrab, Censys):
   ~95% de los eventos IPS. Los paneles nuevos separan el ruido de lo accionable.
5. **Regla 100126 "AD: System audit policy changed - CRITICAL" (Event ID 4719) dispara
   102.980 eventos en 90 días**: segundo generador de ruido masivo (junto al DCSync/MSOL).
   Un volumen así de eventos "CRITICAL" es casi seguro un falso positivo por diseño/tuning.
   Recomendado: tunear 100126 igual que 100123 (bajar nivel o filtrar el origen legítimo).

## Cambios por dashboard

### Dashboard VPN (11 → 14 paneles)
- **"VPN-Gen-AlertasSeguridad"**: la query ahora incluye también `ssl-login-fail`
  (antes solo miraba reglas nivel ≥8).
- NUEVO **"VPN - Logins Fallidos SSL"** (tabla): usuario, IP origen y país de los
  `ssl-login-fail` (60 en los últimos 7 días).
- NUEVO **"VPN - Logins Fallidos Timeline"** (línea).
- NUEVO **"VPN - Tuneles Up vs Down"** (área): tunnel-up vs tunnel-down en el tiempo.
- Rango de tiempo por defecto: últimos 7 días.

### Dashboard NetSecOps (8 → 11 paneles)
- NUEVO **"NetSec - Eventos No-Scanner"** (métrica): eventos IPS excluyendo
  Masscan/ZGrab/Censys/Nmap scanners.
- NUEVO **"NetSec - Ataques Reales (sin scanners)"** (tabla): top ataques e IPs
  excluyendo scanners conocidos.
- NUEVO **"NetSec - Severidad Media-Alta Timeline"** (área): solo severidad
  medium/high/critical en el tiempo.
- Rango de tiempo por defecto: últimos 7 días.

### Dashboard Active Directory (15 → 17 paneles)
Paneles que estaban **muertos** (consultaban reglas inexistentes en este entorno),
reapuntados a Event IDs de Windows reales:
- **"AD - Brute Force Attempts"**: regla 100116 (0 hits) → Event ID **4625** (logon fallido),
  ahora con serie temporal.
- **"AD Summary - Usuarios Creados"**: regla 100080 (0 hits) → Event ID **4720**.
- **"AD - Grupos Privilegiados"**: reglas 100107 (3 hits/90d) / 100108 (0 hits) → Event IDs
  **4728/4732** (altas en grupos admin). Nota: se quitó **4756** del union — no dispara
  nunca en este entorno (0 hits en 90d).
- **"AD - Audit & Log Tampering"**: reglas 100126 (**102.980 hits/90d**, NO 0) / 100127
  (0 hits) → Event ID **1102** (borrado del log de seguridad; 81 hits/90d, señal más
  limpia que la regla ruidosa). Ver corrección y acción sobre 100126 más abajo.

Nuevos:
- **"AD - DCSync Real (sin MSOL)"** (área): regla 100123 excluyendo cuentas `MSOL_*`.
- **"AD - DCSync Benigno filtrado (MSOL)"** (métrica): hace visible cuánto ruido se filtra.
- Rango de tiempo por defecto: últimos 7 días.

### Ranking SQL Access (1 → 5 paneles)
- **"SQL Top IPs"**: tenía 3 filtros rotos (referencias `None`) y sin filtro de regla →
  mostraba cualquier evento Windows. Ahora: `rule.id:"61072"` (MS SQL logon), filtros limpios.
- NUEVO **"SQL - Logons Exitosos"** (métrica, Event ID 18454): ~143.000/semana.
- NUEVO **"SQL - Logons Fallidos"** (métrica, Event ID 18453): ~20.700/semana.
- NUEVO **"SQL - Logons Timeline"** (área): éxito vs fallo en el tiempo.
- NUEVO **"SQL - Accesos con sa"** (tabla): logons del usuario `sa` con IP cliente.
- Rango de tiempo por defecto: últimos 7 días.

### Kong API Gateway Monitoring (10 → 11 paneles)
- Sin cambios en paneles existentes (no hay datos para validarlos).
- NUEVO **"Kong - Aviso sin datos"** (markdown): explica la causa y los pasos para activar
  la integración.

## Notas técnicas

- La regla Wazuh 61072 describe como "MS SQL server logon success" tanto los eventos 18454
  (éxito) como 18453 (fallo). Por eso los paneles nuevos distinguen por Event ID y no por
  descripción de regla. Recomendado revisar esa regla en el ruleset.
- El campo `data.win.eventdata.data` de los eventos SQL combina usuario e IP
  ("sa, [CLIENTE: 192.168.38.27]") en un solo valor; no existe campo separado. Un decoder
  custom podría separarlos y habilitar métricas más finas.
- Script reproducible: `wazuh_dashboards/build_improved.py`
  (lee `original/export_all.ndjson`, genera `improved/improved_all.ndjson`).

## Correcciones post-revisión (verificadas contra el indexer, 2026-07-21)

Segunda revisión cruzando cada afirmación contra conteos reales del indexer. Cambios
aplicados sobre `improved/improved_all.ndjson` (backup: `improved_all.ndjson.bak-pre-correcciones`),
**sin re-importar todavía**:

1. **Rango por defecto del Dashboard AD: `now-7d` → `now-90d`.** Los Event IDs a los que
   se repuntaron los paneles disparan a muy baja frecuencia (4720=0/7d y 10/90d; 1102=0/7d
   y 81/90d; 4728=1/7d y 106/90d; 4625=4/7d y 42/90d). Con 7 días esos paneles críticos se
   veían vacíos igual. El resto de dashboards (VPN/NetSec/SQL, alto volumen) mantiene 7d.
2. **Se quitó Event ID `4756` del panel "Grupos Privilegiados"**: 0 hits en 90d.
3. **Cifras corregidas del informe**: 100126 = **102.980** hits/90d (no 0); 100107 = **3**
   (no 0). Ver hallazgo de seguridad #5 (100126 como fuente de ruido a tunear).

Confirmado y correcto del informe original: Kong = 0 datos, SQL 61072/18454/18453,
DCSync 100123 (~15k/sem), reglas 100116/100080 muertas, `data.win.eventdata.data` combina
usuario+IP.

## Nuevo dashboard: FortiGate Web Filtering — 2026-07-27

Se creó el dashboard **"FortiGate Web Filtering"** (5 paneles, rango por defecto 7d) sobre
las reglas 81620 (URL blocked) y 81644 (denied category) — ~164k eventos/semana que antes
no tenían visualización propia:

- **WF - Bloqueos Timeline** (área, split por `data.profile`)
- **WF - Top Hosts Origen** (tabla, `data.srcip` + `data.dstuser`)
- **WF - Top Usuarios** (tabla, `data.dstuser`)
- **WF - Top Dominios Bloqueados** (tabla, `data.hostname` + `data.profile`)
- **WF - Por Perfil** (tabla, `data.profile`)

Notas técnicas:
- `data.catdesc` NO viene en estos eventos; los campos útiles son `data.hostname`,
  `data.dstuser` y `data.profile` (ej. `WF_VIP`, `certificate-inspection`).
- Script reproducible: `wazuh_dashboards/build_webfilter.py`
  (lee `original/export_pre_webfilter_20260727.ndjson`, genera
  `improved/webfilter_dashboard.ndjson`). Importado vía API sin overwrite (6 objetos
  nuevos, IDs nuevos — no toca objetos existentes).
- Para revertir: borrar el dashboard "FortiGate Web Filtering" y las 5 vis "WF - *"
  desde Stack Management → Saved Objects.

Hallazgo disparador: el host `10.3.200.38` (usuario FALUSTIZA) generaba ~48% del web
filtering (79k bloqueos/sem) hacia dominios `zagent*.{kbz0pwvxmv.com,hola.org,...}`
(proxyware Hola / Bright Data SDK) y `mask.icloud.com` (iCloud Private Relay).
Actividad detenida desde 2026-07-23.

## Dashboard Kong: tabla combinada de alertas — 2026-08-12

El dashboard **"Kong API Gateway Monitoring"** ya cubría 4 de los 5 paneles pedidos
(contador total, códigos HTTP `data.id`, IPs origen `data.srcip`, métodos
`data.protocol` — todos con query `rule.groups: kong`). Se agregó lo único que faltaba:

- **API - Kong Alertas (URL, IP, método, código)** (tabla, `rule.groups: kong`;
  buckets anidados `data.url` → `data.srcip` → `data.protocol` → `data.id`),
  panel ancho completo al final del dashboard (y=88).

Notas técnicas:
- Script reproducible: `wazuh_dashboards/build_kong.py`
  (lee `original/export_pre_webfilter_20260727.ndjson`, genera
  `improved/kong_alertas_tabla.ndjson`: 1 viz nueva + dashboard Kong actualizado).
- Importado vía API con **overwrite=true** el 2026-08-12 (usuario `admin`): la viz
  es nueva (no pisó nada) y el dashboard se subió con su mismo id para agregarle el
  panel. Antes de importar se verificó que el dashboard vivo estaba idéntico al
  export del 2026-07-27 (11 paneles, sin cambios). Quedó con 12 paneles.
- Kong sigue con **0 datos** (ver informe original): los paneles se verán vacíos
  hasta que lleguen alertas con `rule.groups: kong`.
- Para revertir: quitar el panel del dashboard y borrar la viz
  "API - Kong Alertas (URL, IP, método, código)" desde Stack Management → Saved Objects.
