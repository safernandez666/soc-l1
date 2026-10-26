# Catálogo de casos de uso de monitoreo — Wazuh + SOC L1

> Documento de inventario para paquetización comercial.
> Elaborado a partir de la implementación real: reglas y decoders personalizados en el manager,
> ruteo de notificaciones (`ossec.conf`), integrador de email, pipeline SOAR SOC-L1, runbooks del
> repositorio y volumetría observada de alertas (muestra de 7 días + día en curso).
> Anonimizado: sin nombres de cliente, dominios, IPs, hostnames, usuarios ni credenciales.

---

## 1. Resumen

| Métrica | Valor |
|---|---|
| **Casos de uso identificados** | **37** |
| **Reglas personalizadas** (IDs propios) | **113** en 7 archivos |
| **Reglas nativas modificadas** | **2** por `overwrite` (errores de aplicación Windows) + **1** archivo nativo excluido del ruleset (reglas de política/CIS) |
| **Reglas de tuning / supresión** (subconjunto de las personalizadas) | **15** (11 supresiones condicionales de ruido, 3 supresiones de replicación de directorio, 1 degradación de nivel) |
| **Decoders personalizados** | **8 decoders funcionales** en 2 archivos (1 API gateway, 1 padre + 6 hijos para IPS de firewall) + 1 archivo de ejemplo sin uso |
| **Casos con atención formal de SOC L1** (notificación, ticket y/o procedimiento documentado) | **20 de 37** |
| **Casos que generan alerta sin atención formal** | **17 de 37** |

### Desglose de reglas personalizadas por archivo

| Archivo | Reglas | Dominio |
|---|---|---|
| Reglas de Active Directory | 30 | AD / identidad Windows |
| Tuning de AD | 3 | Supresión de replicación legítima y refresco de GPO |
| Reglas locales (`local_rules.xml`) | 14 (2 de ellas `overwrite` de nativas) | Tuning de ruido Windows/web-filtering + ejemplo SSH |
| Reglas IPS de firewall | 32 | Perímetro / IPS-UTM |
| Reglas VPN de firewall | 10 | Acceso remoto / identidad VPN |
| Reglas de EDR (Defender XDR vía Graph) | 6 | Endpoint / EDR |
| Reglas de API Gateway | 20 | Aplicaciones / API |

### Fuentes de logs involucradas

| Fuente | Vía de ingesta | Estado |
|---|---|---|
| Firewall perimetral — IPS/UTM, filtrado web, tráfico | Syslog UDP hacia el manager + decoders propios | Operativo (fuente de mayor volumen) |
| Firewall perimetral — SSL-VPN y autenticación de administración | Syslog UDP, reglas nativas de firewall como padre | Operativo |
| Windows / Active Directory (canal Security de controladores de dominio, servidores y endpoints) | Agente Wazuh (eventchannel) | Operativo |
| Microsoft Defender XDR / Defender for Endpoint (y alertas de correo de la misma consola) | Módulo `azure-logs` → Graph API `security/alerts_v2`, cada 10 min | Operativo |
| Servidores Linux (journald, syslog, gestor de paquetes, comandos periódicos) | Agente Wazuh | Operativo |
| Integridad de archivos y registro (FIM), rootcheck, SCA, inventario y detección de vulnerabilidades | Módulos nativos del agente/manager | Operativo |
| API Gateway | Syslog + decoder propio | Intermitente (flujo de logs no estable) |
| Active Directory por LDAP | Consulta de enriquecimiento del pipeline SOC-L1 (no es fuente de alertas) | Operativo |

**No implementado / sin evidencia en este entorno:** CrowdStrike, ingesta de logs de auditoría de
Microsoft 365 (Exchange/Purview), logs de inicio de sesión de Entra ID, AWS/GCP/Azure Activity.
La única cobertura de correo y de nube proviene de las **alertas** de Defender XDR recibidas por
Graph, no de los logs de auditoría de esas plataformas.

### Cómo se atiende cada alerta (ruteo real)

Las notificaciones **no** salen por el correo nativo de Wazuh (`email_notification` está en `no`).
Todo el ruteo es explícito por integraciones:

1. **Integrador de email unificado** — envía correo con contexto, geolocalización, recomendaciones y
   acciones sugeridas por tipo de alerta. Hoy conserva únicamente: altas/bajas/grupos de AD y cuatro
   reglas nativas de Windows (operación privilegiada fallida, sesión winstation, cuenta creada/habilitada,
   cambio de grupo).
2. **Pipeline SOAR SOC-L1** (webhook con HMAC) — triage LLM → enriquecimiento (AD + API del manager) →
   inteligencia de amenazas (reputación de IP/hash + contexto del firewall) → plan de acción →
   **aprobación humana por link** → ejecutor determinístico. Crea y cierra ticket en la mesa de
   servicio y refleja en el canal de chat corporativo. Recibe: EDR completo, 25 reglas IPS, 5 reglas
   VPN/identidad y las altas/bajas de AD (espejo de chat).
3. **Auto-contención**: 26 reglas IPS/VPN de alta confianza disparan cuarentena de IP en el firewall
   con TTL de 1 h, con ticket abierto y cerrado automáticamente.
4. Todo lo demás queda **solo indexado** (visible en dashboards y en el reporte diario agregado por IA),
   sin notificación ni procedimiento asignado.

---

## 2. Casos de uso

> Convenciones: **Tipo de regla** = `Personalizada` (ID propio), `Nativa` (regla de fábrica sin cambios),
> `Nativa modificada` (sobrescrita o degradada/suprimida por regla hija propia).
> **Estado**: `Operativo` = dispara, se rutea y hay procedimiento; `Parcial` = dispara pero sin
> notificación, sin procedimiento escrito, o con cobertura incompleta; `Deshabilitado` = no puede
> disparar o no hay datos de origen.

### 2.1 Perímetro y red (firewall IPS/UTM)

| Caso de uso | Categoría | Qué detecta | Fuente | Regla Wazuh | Tipo de regla | Validación SOC L1 | Acción SOC L1 | Criterio de escalamiento | Estado |
|---|---|---|---|---|---|---|---|---|---|
| **UC-01 · Ataque de red detectado por IPS, con contención automática de la IP** | Intrusión / perímetro | Eventos IPS clasificados por severidad (crítica, alta, media, baja repetida), ataque efectivamente bloqueado, y correlación de múltiples ataques o ráfagas críticas desde una misma IP | IPS del firewall (syslog + decoder propio) | 196200 (base), 196201, 196202, 196203, 196204, 196205, 196226, 196227, 196228 — padre nativo 81629 | Personalizada (sobre nativa) | Confirmar que la IP de origen es externa y no pertenece a redes propias/partner; verificar reputación de la IP y si el IPS ya la dropeó; revisar si hay sesiones activas y otros destinos atacados | Cuarentena automática de la IP en el firewall (TTL 1 h, redes propias excluidas por guardrail), ticket abierto y cerrado automáticamente, correo/chat de notificación con el detalle | Ataque crítico o ráfaga (196201/196228), destino con servicio expuesto, o sospecha de falso positivo sobre IP legítima → runbook de emergencia y desbloqueo manual | Operativo |
| **UC-02 · Ataque detectado pero NO bloqueado por el IPS** | Gestión de exposición / brecha de control | Eventos con acción "detected" en lugar de "dropped": el IPS vio el ataque y lo dejó pasar (perfil en modo monitor) | IPS del firewall | 196206 (nivel 9), 196207 (crítico no bloqueado, nivel 14) | Personalizada | Verificar si el destino es un activo propio expuesto y si el perfil IPS aplicado al policy está en modo monitor; revisar si hubo tráfico posterior desde la misma IP | Notificación al equipo (correo + chat) y observación registrada; pedido de corrección del perfil IPS al equipo de red | Ataque crítico no bloqueado (196207) → escalamiento inmediato a red/seguridad; cualquier indicio de éxito en el destino → incidente | Operativo |
| **UC-03 · Ataques a aplicaciones web** | Aplicaciones web | Inyección SQL, XSS, inyección de comandos, path traversal, ataques a servidor web genérico, CMS y PHP | IPS del firewall | 196208, 196209, 196210, 196211, 196223, 196224, 196225 | Personalizada | Determinar si el destino publica una aplicación web propia; revisar logs de la aplicación y del WAF; validar si el patrón llegó al backend | Bloqueo automático de la IP para 196208/196210/196223; para el resto, revisión y bloqueo manual si persiste. Recomendaciones específicas por tipo de ataque en el correo (revisar sanitización, WAF, funciones peligrosas) | Inyección de comandos o evidencia de ejecución en el destino → escalamiento a L2 y evaluación de aislamiento del servidor | Parcial — 196209 (XSS), 196211 (path traversal), 196224 y 196225 no están en la lista de reenvío al SOAR ni en la de auto-bloqueo |
| **UC-04 · Exploits, malware y ransomware en tránsito** | Malware / explotación | Buffer overflow, ejecución remota de código, firmas de malware/troyano/gusano, exploit kits y CVE conocidos, actividad de ransomware | IPS del firewall | 196212, 196213, 196220, 196221, 196222 | Personalizada | Verificar dirección del tráfico (entrante vs. saliente); si el origen es interno, tratar como equipo posiblemente comprometido; correlacionar con alertas de EDR del mismo activo | Bloqueo automático de la IP externa; para origen interno, escalamiento y revisión del endpoint en la consola de EDR | Ransomware (196222) o RCE (196213) → escalamiento inmediato, tratamiento como incidente; origen interno → aislar host vía EDR | Operativo |
| **UC-05 · Reconocimiento y escaneo** | Reconocimiento | Escaneos de puertos, escaneo tipo nmap y escáneres de vulnerabilidades conocidos | IPS del firewall | 196214, 196215, 196216 | Personalizada | Confirmar que el escaneo es externo y no proviene de un escáner autorizado propio; verificar qué puertos/servicios respondieron | Bloqueo automático de la IP (196214/196215) con ticket; registro de la campaña de escaneo | Escaneo desde una IP que luego intenta explotación (correlación con UC-01/UC-03) → escalamiento | Operativo — es el caso de mayor disparo real de la familia IPS. 196216 no está reenviada |
| **UC-06 · Denegación de servicio** | Disponibilidad / DoS | DoS, DDoS distribuido y SYN flood contra activos publicados | IPS del firewall | 196217, 196218, 196219 | Personalizada | Verificar impacto real sobre el servicio destino (latencia/caída) y volumen de tráfico | Bloqueo automático de la IP (196217/196218); notificación al equipo de red para mitigación y rate limiting | DDoS confirmado con degradación de servicio → escalamiento a red/proveedor de enlace | Parcial — 196219 (SYN flood) no está reenviada al SOAR |
| **UC-07 · Ataques a servicios de administración remota expuestos** | Superficie de exposición | Ataques dirigidos al puerto de escritorio remoto y al puerto SSH | IPS del firewall | 196230, 196231 | Personalizada | Confirmar si el puerto está realmente publicado hacia Internet; validar si hubo autenticación exitosa posterior | Bloqueo automático de la IP (196230); pedido de cierre/restricción de la publicación | Autenticación exitosa desde IP atacante → incidente de acceso no autorizado | Parcial — 196231 (SSH) no está reenviada |
| **UC-08 · Actividad ofensiva desde países restringidos** | Geolocalización / política | Eventos IPS cuyo país de origen está en la lista restringida | IPS del firewall | 196229 | Personalizada | Validar que el país es efectivamente no operativo para el negocio y que la IP no es un servicio legítimo (CDN/SaaS) | Bloqueo automático de la IP y notificación | Coincidencia con otras señales (VPN, EDR) sobre el mismo activo → escalamiento | Operativo |
| **UC-09 · Filtrado web y navegación bloqueada** | Navegación / política de uso | URLs bloqueadas por el firewall, categorías denegadas por política y múltiples bloqueos desde el mismo origen | Filtrado web del firewall | 81619, 81620, 81635, 81644 — con supresiones propias 110202–110205 | Nativa modificada (supresión por origen) | No definida formalmente | Sin acción individual; consumo por dashboard dedicado de filtrado web y reporte diario | No definido | Parcial — alto volumen (una de las dos reglas más frecuentes del entorno), con dashboard pero sin procedimiento L1 |

### 2.2 Acceso remoto y VPN

| Caso de uso | Categoría | Qué detecta | Fuente | Regla Wazuh | Tipo de regla | Validación SOC L1 | Acción SOC L1 | Criterio de escalamiento | Estado |
|---|---|---|---|---|---|---|---|---|---|
| **UC-10 · Fuerza bruta contra la administración del firewall y acceso administrativo fuera de horario** | Fuerza bruta / acceso privilegiado | 6+ fallos de login administrativo desde una misma IP en 5 minutos; login de cuenta administrativa fuera de horario laboral | Autenticación del firewall | 196100 (padre nativo 81606), 196113 (padre nativo 81605) | Personalizada | Verificar si la IP es de un administrador legítimo; revisar si hubo login exitoso después de los fallos; validar el horario contra la ventana de mantenimiento | Bloqueo automático de la IP (196100) + notificación; para acceso administrativo fuera de horario, verificación con el administrador | Login administrativo exitoso desde IP no reconocida → incidente y rotación de credencial | Parcial — 196100 operativo; 196113 depende de una regla padre nativa que corresponde a otro evento (múltiples descartes de tráfico), por lo que no dispara en la práctica |
| **UC-11 · Fuerza bruta o password spraying contra SSL-VPN** | Fuerza bruta / acceso remoto | 10+ intentos fallidos de login SSL-VPN desde una misma IP en 3 minutos | SSL-VPN del firewall | 196101 (padre nativo 81614) | Personalizada | Identificar si las cuentas objetivo existen; verificar si alguna conexión posterior fue exitosa; revisar reputación de la IP | Bloqueo automático de la IP con ticket; recomendación de verificar estado de las cuentas atacadas y forzar cambio de contraseña si hubo acceso exitoso | Acceso VPN exitoso posterior desde la misma IP → cuenta comprometida, escalamiento y respuesta de identidad | Operativo |
| **UC-12 · Acceso VPN fuera de horario y en fin de semana de usuarios bajo monitoreo** | Uso indebido de cuentas válidas | Conexión SSL-VPN entre 22:00 y 06:00 en días hábiles, o durante el fin de semana; con regla hija que sólo notifica cuando el usuario pertenece a la lista de cuentas monitoreadas (privilegiadas/sensibles) | SSL-VPN del firewall + listas CDB de usuarios monitoreados (sincronizadas a diario desde AD) | 196102 y 196103 (base, todos los usuarios, sin notificación), 196104 y 196105 (usuarios monitoreados) | Personalizada | Confirmar con el usuario si el acceso es autorizado; revisar historial de conexiones y geolocalización habitual; verificar si es cuenta de servicio con tarea nocturna legítima | Pipeline SOAR: triage → enriquecimiento en AD → plan; el plan por defecto es sólo registrar (`notify_only`). Correo de aprobación con timeline y ticket | Señal adicional (IP con mala reputación, país inesperado, múltiples eventos) → subir a escalamiento y evaluar cambio forzado de contraseña | Operativo — las cuentas de servicio están protegidas por lista para que nunca se deshabiliten |
| **UC-13 · Cuenta VPN usada desde múltiples IPs** | Robo de credenciales | Mismo usuario VPN conectando desde 3 IPs distintas en 1 hora | SSL-VPN del firewall | 196107 | Personalizada | Contactar al usuario de inmediato; verificar si tiene sesiones simultáneas; geolocalizar todas las IPs; distinguir cambio de red (fija → móvil) de acceso paralelo real | Plan de respuesta con cambio forzado de contraseña (previa aprobación humana); si las IPs son de ubicaciones distintas, bloqueo de cuenta | IPs de países/ciudades distintas, o usuario que no responde → deshabilitar cuenta y escalar | Operativo — la ejecución de acciones sobre AD está hoy en modo simulación |
| **UC-14 · Viaje imposible: VPN desde múltiples países** | Cuenta comprometida | Mismo usuario conectando desde países distintos en 2 horas | SSL-VPN del firewall | 196109 | Personalizada | Confirmar viaje/roaming real con el usuario y con RRHH; validar si una de las IPs es VPN comercial o proxy | Plan de respuesta con deshabilitación de cuenta + escalamiento a L2 (aprobación humana obligatoria) | Siempre se escala: es la señal más fuerte de compromiso de identidad del pipeline | Operativo — ejecución en AD en modo simulación |
| **UC-15 · Conexión VPN desde país restringido** | Geolocalización / política de acceso | Conexión SSL-VPN cuyo país de origen está en la lista restringida | SSL-VPN del firewall | 196112 | Personalizada | Verificar si el usuario tiene autorización de viaje; validar reputación de la IP | Bloqueo automático de la IP + notificación; verificación con el usuario | Sin autorización de viaje → tratar como cuenta comprometida (UC-14) | Operativo |

### 2.3 Active Directory e identidad Windows

| Caso de uso | Categoría | Qué detecta | Fuente | Regla Wazuh | Tipo de regla | Validación SOC L1 | Acción SOC L1 | Criterio de escalamiento | Estado |
|---|---|---|---|---|---|---|---|---|---|
| **UC-16 · Ciclo de vida de cuentas de usuario en AD** | Gestión de identidades | Creación de cuenta, creación por sesión anónima (sospechoso), eliminación de cuenta, habilitación y deshabilitación | Canal Security de controladores de dominio (agente) | 100080, 100081, 100082, 100109, 100110 + nativa 60109 | Personalizada + nativa | Verificar que el alta/baja fue solicitada por el área correspondiente; validar permisos asignados inicialmente; comprobar si hay otros cambios del mismo actor en la misma ventana | Correo con detalle del evento y acciones sugeridas + espejo en el canal de chat corporativo; documentación en ticket | Creación por sesión anónima (100081), o alta no solicitada / actor inesperado → escalamiento a L2 y revisión del actor | Operativo para 100080/100081/100082 (correo + chat); **Parcial** para 100109/100110 (alertan pero no están ruteadas) |
| **UC-17 · Cambios de membresía en grupos de seguridad** | Gestión de accesos | Alta y baja de miembros en grupos de seguridad locales y globales | Canal Security de controladores de dominio | 100083, 100084, 100085, 100086 + nativa 60113 | Personalizada + nativa | Verificar inmediatamente con el administrador si el cambio fue autorizado; revisar los permisos que otorga el grupo; validar contra política interna | Correo con detalle + espejo en chat; ticket de seguimiento | Grupo con permisos sensibles, o cambio no autorizado → escalamiento y revocación | Operativo (100083/100084/100085 ruteadas; 100086 alerta sin ruteo) |
| **UC-18 · Escalamiento de privilegios: alta en grupos administrativos** | Privilegios administrativos | Alta (nivel 13) y baja (nivel 11) de miembros en grupos privilegiados del dominio: administradores de dominio/empresa/esquema, operadores de cuentas, backup y servidores, administradores de DNS y certificados, creadores de GPO, entre otros | Canal Security de controladores de dominio | 100107, 100108 (hijas de 100083/100084 y 100085/100086) | Personalizada | Validar el ticket de cambio que autoriza la asignación; confirmar con el dueño del grupo; revisar si el actor tenía derecho a hacerlo | **No hay procedimiento asignado**: la alerta se genera con nivel crítico pero no está en ninguna lista de notificación | No definido | Debería escalar siempre; hoy no hay disparador automático | **Parcial — brecha de atención**: dispara (evidencia de altas reales en grupos administrativos en la última semana) sin correo, chat ni ticket |
| **UC-19 · Cambio y reseteo de contraseñas sospechoso** | Credenciales | Cambio de contraseña por el propio usuario, reseteo por un tercero, y reseteo realizado por cuentas con patrón administrativo | Canal Security de controladores de dominio | 100111, 100112, 100113 | Personalizada | Contrastar el reseteo contra el pedido de mesa de servicio; verificar quién fue el actor y si el usuario objetivo es privilegiado | Sin ruteo asignado; sólo consulta en dashboard | No definido | Reseteo de cuenta privilegiada por actor inesperado → escalamiento | **Parcial** — 100111/100112 disparan de forma regular; 100113 cuelga de una regla padre nativa de "cambio de política de auditoría", por lo que su semántica no se cumple y no dispara |
| **UC-20 · DCSync / extracción de credenciales del directorio** | Robo de credenciales | Acceso a objetos del directorio con los GUID de replicación de secretos (patrón DCSync) | Canal Security de controladores de dominio | 100123 (nivel 12) + supresiones propias 110100, 110101, 100223, 100224 | Personalizada con tuning | Identificar la cuenta que solicitó la replicación; si no es la cuenta de sincronización de identidad (patrón `MSOL_*`) ni una cuenta de equipo de controlador de dominio, tratar como intento real | Sin ruteo asignado; el tuning garantiza que sólo el caso no benigno queda visible | No definido | Cuenta de usuario real ejecutando DCSync → incidente de credenciales, escalamiento inmediato | **Parcial** — la detección está afinada y sana (pasó de ~200 mil eventos benignos por trimestre a residuo cero), pero el residuo crítico no dispara notificación |
| **UC-21 · Golden ticket, SID history y delegación Kerberos** | Persistencia / escalamiento | Modificación de SID history (posible golden ticket o escalada) y cambios en la configuración de delegación Kerberos de una cuenta | Canal Security de controladores de dominio | 100124, 100128 | Personalizada | Validar contra cambios autorizados de infraestructura; revisar el actor y el objeto modificado | Sin ruteo asignado | No definido | Cualquier disparo debería escalar (técnicas de persistencia de dominio) | **Parcial** — sin eventos en la muestra de 7 días; sin notificación asignada |
| **UC-22 · Anti-forense: cambio de política de auditoría y borrado del log de seguridad** | Evasión de defensas | Cambio de política de auditoría del sistema (nivel 13) y limpieza del registro de eventos de seguridad (nivel 12) | Canal Security de servidores y controladores de dominio | 100126 + degradación propia 100146 y supresión 100226; 100127; nativa 60112 | Personalizada con tuning | Determinar si el actor es cuenta de equipo (refresco de GPO, benigno) o cuenta de usuario real; en el segundo caso, revisar qué subcategorías se modificaron y correlacionar con otra actividad del actor | Sin ruteo asignado; el tuning suprime el refresco de GPO por cuenta de equipo | No definido | Cambio de política o borrado de log por cuenta de usuario → incidente, escalamiento inmediato | **Parcial** — tuning efectivo (de ~103 mil eventos por trimestre a residuo). Trade-off documentado: un cambio malicioso ejecutado como cuenta de sistema también queda suprimido |
| **UC-23 · Modificación de políticas de grupo (GPO)** | Cambios críticos de configuración | Cambios en objetos de directiva de grupo (creación, modificación y borrado de atributos de GPO) | Canal Security de controladores de dominio | 100122 (nivel 9) | Personalizada | Validar contra ventana de cambio autorizada; identificar la GPO afectada y su alcance | Sin ruteo asignado | No definido | GPO de seguridad modificada fuera de ventana de cambio → escalamiento | **Parcial** — es la regla personalizada de AD que más dispara (cientos de eventos por semana), sin procedimiento ni notificación; candidata a tuning o a caso de uso de gestión de cambios |
| **UC-24 · Cambios en cuentas de equipo del dominio** | Gestión de activos / persistencia | Modificación de cuentas de equipo (incluye alta de equipos al dominio y cambios de atributos) | Canal Security de controladores de dominio | 100125 (nivel 8) | Personalizada | Verificar si el equipo corresponde a un alta legítima de inventario; revisar el actor | Sin ruteo asignado | No definido | Cuenta de equipo creada por un usuario no autorizado (abuso de cuota de creación de equipos) → escalamiento | **Parcial** — decenas de eventos por semana, sin procedimiento |
| **UC-25 · Kerberoasting y AS-REP roasting** | Robo de credenciales | Solicitud masiva de tickets de servicio por un mismo usuario (kerberoasting) y fallo de pre-autenticación Kerberos con estado de cuenta sin pre-auth (AS-REP roasting); reglas base de TGT y ticket de servicio | Canal Security de controladores de dominio | 100118, 100119, 100120, 100121 | Personalizada | Identificar el principal solicitante y la cantidad de SPN distintos consultados | No aplicable hoy | No aplicable hoy | — | **Deshabilitado de hecho** — 100119 y 100121 cuelgan de reglas padre nativas que corresponden a otros eventos (logon exitoso de estación y evento duplicado/ignorado); 0 disparos en la muestra. Requiere rehacer el encadenamiento y verificar la auditoría de Kerberos en los DC |
| **UC-26 · Fuerza bruta o password spraying contra cuentas de usuario Windows** | Fuerza bruta | Logon fallido, logon exitoso, logoff y correlación de 5 fallos en 2 minutos desde la misma IP | Canal Security de servidores y controladores de dominio | Personalizadas 100114, 100115, 100116, 100117 (sin efecto) — cobertura efectiva por nativas 60122 (fallo de logon por usuario/contraseña incorrecta), 60104 (fallo de auditoría), 60115 (bloqueo de cuenta) | Personalizada (inefectiva) + nativa | Identificar cuenta y origen; verificar si hubo logon exitoso posterior; revisar si la cuenta terminó bloqueada | Sin ruteo asignado para las reglas nativas que sí disparan | No definido | Logon exitoso tras ráfaga de fallos → cuenta comprometida | **Parcial** — las reglas personalizadas cuelgan del evento de auditoría **exitosa** y quedan además tapadas por reglas nativas, por lo que no disparan; el volumen de eventos de logon fallido recolectado es muy bajo (unidades por día), lo que sugiere auditoría de fallos incompleta en el origen |
| **UC-27 · Operación privilegiada fallida y actividad de sesión en Windows** | Privilegios / auditoría | Intento fallido de realizar una operación privilegiada; reconexión/desconexión de sesión winstation | Canal Security/System de servidores Windows | Nativas 60107, 60108 | Nativa (ruteada explícitamente) | Revisar el contexto del intento y si el usuario debería tener el privilegio | Correo con detalle y recomendación genérica de revisión de logs | Patrón repetido sobre el mismo activo/usuario, o combinación con otros eventos de privilegios → escalamiento | Operativo con salvedad — es una de las reglas de mayor volumen del entorno (miles de eventos por día) y su recomendación en correo es genérica; candidata a tuning |

### 2.4 Endpoint / EDR y correo

| Caso de uso | Categoría | Qué detecta | Fuente | Regla Wazuh | Tipo de regla | Validación SOC L1 | Acción SOC L1 | Criterio de escalamiento | Estado |
|---|---|---|---|---|---|---|---|---|---|
| **UC-28 · Alertas de EDR por severidad (malware, acceso inicial, comportamiento)** | Malware / endpoint | Toda alerta de la consola de EDR/XDR clasificada en informativa, baja, media y alta: malware prevenido o activo, acceso inicial, comportamiento sospechoso | Graph API de la consola de EDR (módulo `azure-logs`), cada 10 min | 200000 (base), 200001, 200002, 200003, 200004 — padre nativo 87802 | Personalizada | Leer el estado de remediación del archivo (prevenido/en cuarentena vs. activo/no encontrado), la familia de la amenaza, el nivel de riesgo del equipo y las acciones recomendadas por el fabricante; validar hash en fuentes de reputación; confirmar actividad con el usuario | Pipeline SOAR completo: triage, enriquecimiento en AD y en el manager, reputación de hash/IP, plan de acción con aprobación humana. Acciones disponibles: análisis antivirus del equipo, aislamiento de red del equipo, cambio forzado de contraseña, deshabilitación de cuenta. Ticket creado y cerrado con timeline por agente | Severidad alta (200004), amenaza no remediada, equipo con riesgo alto, o familia de robo de credenciales/RAT/ransomware → aislar equipo y escalar a L2 | Operativo — las acciones sobre el EDR están hoy en modo simulación (pendiente de habilitación de credenciales de respuesta) |
| **UC-29 · Herramientas de crackeo, keygen y HackTool** | Software no autorizado | Alertas informativas del EDR cuyo título corresponde a keygen, crack, activador, parcheador, HackTool o secuestro del archivo de hosts (elevadas de informativo a nivel 7) | Graph API de la consola de EDR | 200005 (hija de 200001) | Personalizada | Confirmar el equipo y el usuario; determinar si es software pirata instalado a propósito; revisar si el EDR lo previno | Notificación y ticket; documentación del hallazgo y pedido de remediación al usuario/soporte | Reincidencia en el mismo equipo, o herramienta con capacidad de robo de credenciales → escalamiento | Operativo |
| **UC-30 · Amenazas de correo reportadas por la consola de EDR/XDR** | Correo / phishing | Alertas de la consola relativas a correo: mensajes eliminados después de la entrega, correo reportado por usuarios como no deseado / no malicioso | Graph API de la consola de EDR (mismo canal que UC-28) | 200001, 200002 (por título) | Personalizada (sin regla específica por título de correo) | Validar en el portal de correo si hubo entrega y clics; revisar destinatarios alcanzados | Entra al pipeline SOAR como alerta de EDR genérica; sin tratamiento específico de campaña de phishing | Campaña con múltiples destinatarios o clic confirmado → escalamiento a L2 | **Parcial** — cobertura incidental: llega por el canal de alertas del EDR, sin ingesta de logs de auditoría de la plataforma de correo ni regla dedicada |

### 2.5 Plataforma Windows y Linux

| Caso de uso | Categoría | Qué detecta | Fuente | Regla Wazuh | Tipo de regla | Validación SOC L1 | Acción SOC L1 | Criterio de escalamiento | Estado |
|---|---|---|---|---|---|---|---|---|---|
| **UC-31 · Integridad de archivos y registro (FIM)** | Integridad / cambios críticos | Cambios de checksum en valores y claves de registro de Windows, alta y baja de entradas de registro; en Linux, cambios en directorios de binarios y configuración del sistema, con alerta de archivos nuevos | Módulo de integridad del agente (Windows y Linux) | Nativas 594, 597, 598, 750, 751, 752 (y familia syscheck) | Nativa | No definida | Sin acción individual; consumo por dashboard | No definido | **Parcial** — miles de eventos por día (tercera fuente de volumen del entorno) sin procedimiento de análisis; candidato inmediato a tuning y a definición de líneas base |
| **UC-32 · Anomalías de host, rootkits y cumplimiento de configuración** | Higiene / hardening | Detección de anomalías de host y rootkits (rootcheck, cada 12 h) y evaluación de configuración segura (SCA, cada 12 h) | Módulos nativos del agente | Nativas familia 510 y SCA | Nativa | No definida | Sin acción; consumo por dashboard | No definido | Parcial — módulos activos y disparando, sin procedimiento L1 |
| **UC-33 · Errores de aplicación y servicios en endpoints Windows** | Disponibilidad / higiene del SIEM | Errores de aplicación y de sistema, terminación de procesos por excepción no controlada, resumen de firmas de antivirus, correlación de múltiples errores | Canal Application/System de Windows | **Nativas modificadas por `overwrite`**: 60602 y 61017 (bajadas de nivel 9 a 5); supresiones propias 110206, 110207, 110208; nativas 61061, 61102, 61107, 61110, 60608 | Nativa modificada | No definida (no son eventos de seguridad) | Sin acción | No definido | Operativo informativo — el tuning fue deliberado: estas dos reglas representaban ~85 % de las alertas de nivel ≥ 8 del entorno |
| **UC-34 · Autenticación SSH en servidores Linux** | Autenticación | Fallo de autenticación SSH | journald/syslog del agente Linux | 100001 (regla de ejemplo con IP fija) + nativas de la familia SSH | Personalizada (plantilla) | No definida | Sin acción | No definido | **Deshabilitado** — 100001 es la regla de ejemplo del ruleset con una IP de demostración; no aporta detección. Las reglas nativas de SSH siguen activas pero sin ruteo |
| **UC-35 · Logon remoto e inicio de sesión local en Windows** | Accesos y autenticaciones | Logon remoto exitoso por escritorio remoto, logon local no de red ni de servicio, cierre de sesión, asignación de privilegios especiales al inicio de sesión, creación de procesos | Canal Security de servidores y endpoints | Nativas 67022, 67023, 67027, 67028, 92653, 92657, 60106, 60137 | Nativa | No definida | Sin acción individual | No definido | Parcial — volumen alto y sostenido (miles de eventos por día), útil como base de detección de accesos pero sin caso de uso formalizado |

### 2.6 API Gateway

| Caso de uso | Categoría | Qué detecta | Fuente | Regla Wazuh | Tipo de regla | Validación SOC L1 | Acción SOC L1 | Criterio de escalamiento | Estado |
|---|---|---|---|---|---|---|---|---|---|
| **UC-36 · Abuso de autenticación y enumeración en API Gateway** | Aplicaciones / API | 401 individuales y 5+ 401 desde la misma IP en 1 min (credential stuffing), 403 prohibidos, 404 individuales y 10+ 404 en 2 min (enumeración de endpoints), exceso de rate limit, 10+ errores de cliente en 1 min y 20+ requests en 1 min desde la misma IP | Logs del API Gateway (syslog + decoder propio que extrae IP, método, URL y código) | 100203, 100204, 100205, 100206, 100207, 100208, 100240, 100241 | Personalizada | Identificar consumidor y credencial usada; distinguir cliente mal configurado de intento de abuso | Sin ruteo asignado | No definido | Credential stuffing con éxito posterior (2xx tras ráfaga de 401) → escalamiento | **Parcial** — reglas y decoder completos, pero el flujo de logs es intermitente (sólo un día con eventos en la última semana): requiere restablecer el envío de logs del gateway |
| **UC-37 · Salud del servicio y auditoría de operaciones sensibles en API Gateway** | Disponibilidad / auditoría | Errores 5xx y correlación de 5+ en 2 min (degradación o caída del servicio); operaciones de creación, modificación y borrado; accesos a endpoints de autenticación y de prueba | Logs del API Gateway | 100200, 100201, 100202, 100210, 100211, 100220, 100221, 100222, 100230, 100231, 100232, 100233 | Personalizada | Correlacionar degradación con despliegues; validar autoría de operaciones de borrado | Sin ruteo asignado | No definido | Caída del servicio o borrado no autorizado → escalamiento al equipo de aplicaciones | **Parcial** — mismo problema de flujo de logs; varias reglas apuntan a endpoints de un servicio de prueba (herencia de la etapa de laboratorio) |

---

## 3. Reglas que generan alertas sin procedimiento SOC L1

Reglas activas y disparando, pero sin criterio de validación ni de escalamiento documentado, y en
la mayoría de los casos sin ruta de notificación (ni correo, ni chat, ni ticket).

### 3.1 Personalizadas críticas sin notificación (brecha de mayor impacto)

| Regla(s) | Nivel | Detección | Situación |
|---|---|---|---|
| 100107, 100108 | 13 / 11 | Alta y baja en grupos administrativos del dominio | Dispara con eventos reales; **no está en ninguna lista de notificación** |
| 100122 | 9 | Modificación de GPO | Regla personalizada de AD con mayor volumen; sin ruteo ni procedimiento |
| 100123 (residuo tras tuning) | 12 | DCSync por cuenta no whitelisteada | Detección afinada, sin notificación del residuo crítico |
| 100126 (residuo), 100127 | 13 / 12 | Cambio de política de auditoría por cuenta de usuario; borrado del log de seguridad | Sin notificación; técnicas de evasión de defensas |
| 100124, 100128 | 12 / 10 | SID history; delegación Kerberos | Sin notificación |
| 100109, 100110, 100111, 100112 | 7 / 7 / 5 / 8 | Habilitación y deshabilitación de cuenta; cambio y reseteo de contraseña | Disparan de forma regular; sin ruteo (a diferencia de 100080–100085) |
| 100125 | 8 | Cambios en cuentas de equipo | Decenas por semana, sin procedimiento |
| 100086 | 7 | Baja de miembro de grupo global | Excluida de la lista de correo que sí incluye a sus hermanas |
| 196209, 196211, 196216, 196219, 196224, 196225, 196231 | 8–10 | XSS, path traversal, escáner de vulnerabilidades, SYN flood, ataques a CMS/PHP, ataques a SSH | Alertan pero no se reenvían al pipeline SOAR ni entran en la lista de auto-bloqueo |
| 196205 | 5 | Ataque bloqueado por el IPS | Se reenvía al pipeline pero está fuera de la lista de auto-bloqueo (queda como observación) |
| 100200–100241 (familia API Gateway) | 3–10 | Todo el caso de uso de API | Sin ruteo y con flujo de logs intermitente |

### 3.2 Nativas de alto volumen sin procedimiento

> Volúmenes tomados de la jornada en curso (día parcial, ~10 h): son órdenes de magnitud, no totales diarios cerrados.

| Regla(s) | Volumen observado | Detección |
|---|---|---|
| 81620, 81633, 81635, 81644, 81619 | ~7 mil/día (las dos primeras son las reglas más frecuentes del entorno) | Filtrado web: URL bloqueada, aplicación permitida, categoría denegada, tráfico alto |
| 750, 594, 752, 751, 597, 598 | ~4,7 mil/día | Integridad de registro y archivos (FIM) |
| 60104 | ~2,2 mil/día | Fallo de auditoría de Windows (con una supresión por servidor ya aplicada) |
| 60107, 60108 | ~1,9 mil/día | Operación privilegiada fallida y sesión winstation — tienen correo, pero con texto de recomendación genérico |
| 60602, 61017, 61061, 61102, 61107, 61110, 60608 | ~3 mil/día | Errores de aplicación y sistema (ya degradados de nivel por tuning) |
| 67022, 67023, 67027, 67028, 60106, 60137, 92653, 92657 | ~2,5 mil/día | Logon local, logoff, creación de proceso, privilegios especiales, logon remoto por escritorio remoto |
| 60227, 60228 | decenas/día | Dispositivo externo reconocido; tarea programada creada (ambas relevantes para seguridad, sin procedimiento) |
| 61104, 60642, 60702, 60790, 60132, 60646, 90512 | decenas/día | Cambios de tipo de arranque de servicios, activación de licencias, cambio de hora del sistema, protección que requiere reinicio |
| Familia 510 y SCA | Periódico (cada 12 h) | Rootcheck y evaluación de configuración segura |
| Detección de vulnerabilidades e inventario | Continuo | Módulos activos; su explotación es por reporte semanal, no por alerta |

### 3.3 Reglas personalizadas sin efecto (no pueden disparar como están escritas)

| Regla(s) | Problema detectado |
|---|---|
| 100114, 100115, 100116, 100117 | Cuelgan del evento de auditoría **exitosa** (incluso las de logon fallido) y quedan tapadas por reglas nativas equivalentes; 0 disparos en 7 días |
| 100118, 100119, 100120, 100121 | Encadenamiento a reglas padre nativas que corresponden a otros eventos (logon exitoso de estación, evento duplicado/ignorado); Kerberoasting y AS-REP roasting no operativos |
| 100113 | Cuelga de la regla nativa de cambio de política de auditoría, no del evento de reseteo de contraseña |
| 196113 | Cuelga de la regla nativa de múltiples descartes de tráfico, no del login administrativo |
| 100001 | Regla de ejemplo del ruleset, con IP de demostración fija |
| 196229, 196112 | El país restringido está embebido como literal en la regla (una sola geografía cubierta) |
| 196104, 196105 | La lista de usuarios monitoreados está embebida como expresión regular dentro de la regla, en paralelo a las listas CDB existentes: dos fuentes de verdad para el mismo dato |

---

## 4. Procedimientos SOC L1 sin regla de Wazuh identificada

| Procedimiento / instructivo | Dónde está documentado | Regla asociada |
|---|---|---|
| **Runbook de auto-contención en firewall** (fases observar → cutover → rollback, con backups verificados por checksum) | Runbook del repositorio | Operativo sobre UC-01 a UC-08, pero es un procedimiento de operación, no de detección |
| **Runbook de emergencia de auto-contención** (kill-switch quirúrgico y maestro, verificación de configuración efectiva, desbloqueo manual de una IP, criterios de quién/cuándo, documentación del evento) | Runbook del repositorio | Sin regla: se activa por decisión humana o pedido de negocio |
| **Reporte diario por IA** (cron 18:00): resumen de alertas por nivel, comparación con el período previo, top de IPs bloqueadas, nivel de riesgo estimado | Script fuera del repositorio | Agregado por nivel de regla, no ligado a reglas concretas |
| **Reporte semanal de vulnerabilidades y cumplimiento de parches** con comparación histórica (snapshots semanales) | Script de plataforma | Usa el módulo de detección de vulnerabilidades por API; no hay reglas de alerta |
| **Reporte semanal de bloqueos automáticos** | Mismo script del reporte diario | Se alimenta de los eventos de bloqueo, no de una regla propia |
| **Sincronización diaria de administradores de AD hacia la lista de usuarios VPN monitoreados** (cron 06:30, con correo si hubo diferencias) | Script de plataforma | Alimenta UC-12; no genera alertas propias |
| **Higiene del SIEM (CleanSwarm) y Wazuh Health** (timer diario): detección de reglas ruidosas, recomendación de supresión condicional con simulación histórica de impacto y nota de rollback; capacidad, cobertura de agentes y reglas sin disparos | Documentos del repositorio + módulo propio | Procedimiento de plataforma, sin reglas de detección |
| **Reconciliación de tickets en la mesa de servicio** (barrido periódico, verificación de cierre por lectura, script de huérfanos) | Módulo y script del repositorio | Procedimiento de cierre, sin regla |
| **Procedimiento de conexión desde red anónima (TOR/proxy)**: el integrador de correo tiene recomendación y acciones sugeridas completas para la regla 196106 | Integrador de email | **La regla 196106 no existe en el ruleset**: procedimiento escrito sin detección detrás |
| **Procedimiento de desbloqueo con herramienta heredada** (comando de unblock del script anterior) mencionado en las acciones sugeridas del correo | Integrador de email | Corresponde al mecanismo anterior de bloqueo permanente, no al actual con TTL |
| **Respuesta sobre identidad y endpoint** (deshabilitar cuenta, forzar cambio de contraseña, análisis antivirus, aislamiento de equipo) | Ejecutor del pipeline + plan del agente narrador | Capacidad implementada y probada, pero en **modo simulación** para AD y EDR: hoy no hay ejecución real fuera de la contención de IP |

---

## 5. Lista para paquetizar

Madurez: **Alta** = detección + ruteo + procedimiento + evidencia de operación; **Media** = detección
operativa con procedimiento parcial o respuesta simulada; **Baja** = detección presente pero sin
ruteo/procedimiento, o requiere corrección técnica antes de venderse.

| Paquete sugerido | Caso de uso | Fuente requerida | Incluye monitoreo SOC L1 | Madurez |
|---|---|---|---|---|
| **Monitoreo de VPN y FortiGate** | UC-01 Ataques IPS con contención automática de IP | Firewall con IPS/UTM, syslog al SIEM | Sí — triage, ticket y contención automática con TTL | Alta |
| Monitoreo de VPN y FortiGate | UC-02 Ataque detectado y no bloqueado por el IPS | Firewall con IPS en modo monitor | Sí — notificación y pedido de corrección de perfil | Alta |
| Monitoreo de VPN y FortiGate | UC-05 Reconocimiento y escaneo de puertos/vulnerabilidades | Firewall con IPS | Sí | Alta |
| Monitoreo de VPN y FortiGate | UC-06 Denegación de servicio | Firewall con IPS | Sí (parcial: SYN flood sin ruteo) | Media |
| Monitoreo de VPN y FortiGate | UC-07 Ataques a servicios de administración remota expuestos | Firewall con IPS | Sí (SSH sin ruteo) | Media |
| Monitoreo de VPN y FortiGate | UC-08 / UC-15 Actividad y acceso desde países restringidos | Firewall con geolocalización | Sí | Media — la geografía está embebida en la regla |
| Monitoreo de VPN y FortiGate | UC-10 Fuerza bruta contra la administración del firewall | Autenticación del firewall | Sí | Media — la variante "fuera de horario" requiere corrección |
| Monitoreo de accesos y autenticaciones | UC-11 Fuerza bruta o password spraying contra SSL-VPN | SSL-VPN del firewall | Sí — contención automática de la IP | Alta |
| Monitoreo de accesos y autenticaciones | UC-12 Acceso VPN fuera de horario y fin de semana de usuarios sensibles | SSL-VPN + AD (lista de cuentas monitoreadas, sincronizada a diario) | Sí — pipeline completo con aprobación humana | Alta |
| Monitoreo de accesos y autenticaciones | UC-13 Cuenta VPN desde múltiples IPs | SSL-VPN + AD | Sí — plan con cambio forzado de contraseña | Media — ejecución en AD simulada |
| Monitoreo de accesos y autenticaciones | UC-14 Viaje imposible (multi-país) | SSL-VPN con geolocalización + AD | Sí — plan con deshabilitación de cuenta + escalamiento | Media — ejecución en AD simulada |
| Monitoreo de accesos y autenticaciones | UC-26 Fuerza bruta contra cuentas de usuario Windows | Canal Security de DC/servidores con auditoría de fallos habilitada | No | Baja — requiere rehacer las reglas y verificar auditoría en el origen |
| Monitoreo de accesos y autenticaciones | UC-35 Logon remoto e inicio de sesión local | Canal Security de servidores y endpoints | No | Baja |
| **Monitoreo de Active Directory** | UC-16 Ciclo de vida de cuentas de usuario | Canal Security de controladores de dominio | Sí — correo con contexto + espejo en chat + ticket | Alta |
| Monitoreo de Active Directory | UC-17 Cambios de membresía en grupos de seguridad | Canal Security de DC | Sí | Alta |
| Monitoreo de Active Directory | UC-19 Cambio y reseteo de contraseñas | Canal Security de DC | No | Baja — falta ruteo; una regla requiere corrección |
| Monitoreo de Active Directory | UC-24 Cambios en cuentas de equipo del dominio | Canal Security de DC | No | Baja |
| **Monitoreo de privilegios administrativos** | UC-18 Alta y baja en grupos administrativos del dominio | Canal Security de DC | No (brecha) | Baja — detección lista y probada; sólo falta ruteo y procedimiento |
| Monitoreo de privilegios administrativos | UC-27 Operación privilegiada fallida en Windows | Canal Security de servidores | Sí — correo | Media — requiere tuning por volumen |
| **Monitoreo de cambios críticos** | UC-23 Modificación de políticas de grupo (GPO) | Canal Security de DC | No | Baja — alto volumen, requiere tuning previo |
| Monitoreo de cambios críticos | UC-22 Cambio de política de auditoría y borrado del log de seguridad | Canal Security de servidores y DC | No | Media — tuning maduro y documentado, falta ruteo |
| Monitoreo de cambios críticos | UC-31 Integridad de archivos y registro (FIM) | Módulo de integridad en agentes Windows/Linux | No | Baja — requiere líneas base y tuning |
| **Monitoreo de credenciales de directorio** | UC-20 DCSync / extracción de credenciales del directorio | Canal Security de DC con auditoría de acceso a objetos | No | Media — tuning de altísimo valor demostrado (de ~200 mil eventos benignos por trimestre a residuo cero) |
| Monitoreo de credenciales de directorio | UC-21 SID history y delegación Kerberos | Canal Security de DC | No | Baja |
| Monitoreo de credenciales de directorio | UC-25 Kerberoasting y AS-REP roasting | Canal Security de DC con auditoría Kerberos | No | Baja — requiere rehacer el encadenamiento de reglas |
| **Monitoreo de EDR** | UC-28 Alertas de EDR por severidad | Consola de EDR/XDR con acceso a API (alertas) | Sí — pipeline completo, ticket con timeline y respuesta con aprobación humana | Alta (respuesta sobre endpoint simulada) |
| Monitoreo de EDR | UC-29 Herramientas de crackeo, keygen y HackTool | Consola de EDR/XDR | Sí | Alta |
| **Monitoreo de malware** | UC-04 Exploits, malware y ransomware en tránsito | Firewall con IPS/AV | Sí — contención automática | Alta |
| Monitoreo de malware | UC-28 (vertiente de malware en endpoint) | Consola de EDR/XDR | Sí | Alta |
| **Monitoreo de aplicaciones web** | UC-03 Inyección SQL, XSS, comandos y path traversal | Firewall con IPS (idealmente WAF) | Sí (parcial) | Media |
| **Monitoreo de Microsoft 365** | UC-30 Amenazas de correo reportadas por la consola de EDR/XDR | Consola de EDR/XDR (cobertura incidental) | Parcial | Baja — requiere ingesta real de auditoría de correo/Entra ID, no implementada |
| **Monitoreo de navegación y filtrado web** | UC-09 URLs y categorías bloqueadas | Filtrado web del firewall | No | Baja — hay dashboard, falta procedimiento |
| **Monitoreo de endpoints Windows** | UC-33 Errores de aplicación y servicios (con tuning de ruido) | Canales Application/System de Windows | No | Media — el valor comercial acá es el **paquete de tuning** (redujo ~85 % de las alertas de nivel ≥ 8) |
| **Monitoreo de servidores Linux** | UC-32 Rootcheck y cumplimiento de configuración | Agente Linux (rootcheck + SCA) | No | Baja |
| Monitoreo de servidores Linux | UC-34 Autenticación SSH | Agente Linux (journald/syslog) | No | Baja — sólo la regla de ejemplo del ruleset |
| **Monitoreo de API Gateway** | UC-36 Abuso de autenticación y enumeración | Logs del gateway al SIEM + decoder propio | No | Baja — reglas y decoder completos, flujo de logs intermitente |
| Monitoreo de API Gateway | UC-37 Salud del servicio y auditoría de operaciones sensibles | Logs del gateway | No | Baja |
| **Servicios transversales empaquetables** (no son casos de uso de detección, pero son diferenciadores vendibles) | Triage automático con IA + aprobación humana; contención automática con TTL y guardrails de redes protegidas; runbook de emergencia; ticketing con cierre verificado y reconciliación; espejo en chat corporativo; reporte diario por IA; reporte semanal de vulnerabilidades; higiene del SIEM con simulación de impacto | SIEM + mesa de servicio + chat corporativo | Sí | Alta |

---

## Notas de cierre para el armado comercial

1. **Lo más maduro y diferenciador** es el bloque de perímetro/VPN con contención automática y el
   bloque de EDR con triage por IA y aprobación humana: tienen detección, ruteo, ticket, runbook de
   operación y runbook de emergencia, con evidencia de funcionamiento continuo.
2. **La brecha más rentable de cerrar** es Active Directory: hay 30 reglas personalizadas de buena
   factura, pero sólo 6 tienen ruta de notificación. Cerrar el ruteo de privilegios administrativos,
   DCSync, política de auditoría y borrado de logs convierte trabajo ya hecho en tres paquetes
   vendibles sin desarrollo nuevo.
3. **Hay 11 reglas personalizadas que no disparan como están escritas** (0 eventos en la muestra):
   las cuatro de autenticación Windows, las cuatro de Kerberos, la de reseteo de contraseña por
   actor administrativo, la de login administrativo del firewall y la de ejemplo de SSH. La causa
   en todos los casos es encadenamiento a una regla padre nativa que corresponde a otro evento (o
   sombreado por reglas nativas equivalentes). Corregirlas es requisito para vender los paquetes de
   autenticación y de credenciales de directorio.
4. **El tuning es producto en sí mismo**: las supresiones aplicadas están documentadas con
   volumetría antes/después, simulación de impacto, nota de rollback y trade-offs explícitos. Es un
   entregable de "reducción de ruido del SIEM" empaquetable de forma independiente de las
   detecciones.
5. **Modo de respuesta actual**: sólo la contención de IP en el firewall se ejecuta en vivo. Las
   acciones sobre AD y sobre el EDR están implementadas, probadas y en modo simulación — al
   paquetizar, presentarlas como "respuesta asistida con aprobación humana, habilitable por fase".
