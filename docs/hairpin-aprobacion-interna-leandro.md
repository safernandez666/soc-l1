# Hairpin de aprobación interna — para Leandro (red / FortiGate)

> **Síntoma:** un approver **en la red interna / LAN** (o el propio server) que hace clic
> en el link de aprobación `https://socl1.grupoalemana.com/review/<token>` recibe
> **HTTP 504 (timeout)**. Desde **internet (4G/datos móviles) funciona perfecto** — validado E2E.
> **Esto NO es una falla del SOC-L1 ni del reboot.** Es hairpin NAT en el FortiGate.
> Host backend: `seg-vs85-prod01` (`192.168.38.60:8000`, HTTP plano) · Última actualización: 2026-06-23.

---

## TL;DR

- El path público anda bien para usuarios **externos**. El problema es **solo interno** (hairpin).
- Causa: el **access-proxy `AP-SOCL1`** del FortiGate reenvía al realserver `192.168.38.60:8000`
  **preservando la IP de origen del cliente**. Cuando el cliente está en la LAN, el paquete vuelve
  al server con un origen de la propia subred (y, si es el mismo server, con su **propia IP**) →
  el kernel del backend lo descarta (`net.ipv4.conf.eth0.accept_local=0`, anti-martian) → nunca hay
  SYN-ACK → el FortiGate corta a los ~10 s con **504**.
- **Fix (lado FortiGate):** habilitar **SNAT en el tramo hairpin** (FortiGate → realserver) para que el
  origen pase a ser una IP del propio FortiGate en lugar de la del cliente. Con eso el backend deja de
  verlo como martian y completa el handshake.

---

## Topología actual (lo que hay hoy)

```
Cliente ─HTTPS:443─> 200.41.220.53 (VIP-SOCL1, interfaz wan/Movistar)
                       │  FortiGate termina TLS (cert: wildcard_grupoalemana)
                       │  access-proxy AP-SOCL1 (type=access-proxy, ssl-mode=half)
                       └─HTTP:8000─> realserver 192.168.38.60:8000  (seg-vs85-prod01, soc-l1)
```

Objetos relevantes en el FortiGate (`192.168.32.1`, vdom root):

| Objeto | Valor |
|---|---|
| VIP | `VIP-SOCL1` — extip `200.41.220.53:443`, `type=access-proxy`, cert `wildcard_grupoalemana` |
| Access-proxy | `AP-SOCL1` (vip=VIP-SOCL1), api-gateways url-map `/health` `/approve` `/reject` `/decide` `/review` |
| Realserver | `192.168.38.60:8000` (HTTP plano — el FGT termina TLS) |
| Interfaz lan | `192.168.32.1/20` (hard-switch); el backend `192.168.38.60` está en la misma subred |

> El backend escucha en `0.0.0.0:8000` y responde 200 a tráfico legítimo. No hay firewall de host
> bloqueando (UFW está **inactivo**). El backend es sano.

---

## Evidencia (por qué sabemos que es hairpin y no otra cosa)

`tcpdump` en el backend (`eth0`, `tcp port 8000`) mientras se golpea el link público **desde el server**:

```
19:12:27 IP 192.168.38.60.9045 > 192.168.38.60.8000: Flags [S] ...
19:12:27 IP 192.168.38.60.9046 > 192.168.38.60.8000: Flags [S] ...
(… SYN reintentándose, sin SYN-ACK …)
```

- El SYN **llega** al `:8000`, pero con **origen `192.168.38.60`** (la propia IP del backend), no con la
  IP del FortiGate → el access-proxy preservó el origen del cliente (que en el hairpin desde el server
  es su propia IP).
- `net.ipv4.conf.{eth0,all}.accept_local = 0` → el kernel descarta paquetes que llegan por eth0 con
  origen = una IP local → **drop silencioso** (`log_martians=0`, por eso no aparece en dmesg).
- Resultado: sin SYN-ACK → el FortiGate corta con **504** a los 10 s.

Contraprueba: desde **internet** (IP pública `181.97.71.198`) el mismo link dio **200**, aprobación OK,
ejecución OK, mail de cierre OK. El path externo está validado E2E.

---

## Fix propuesto (a aplicar por Leandro, en el FortiGate)

La idea es **NAT-ear el tramo hairpin** para que el realserver vea como origen una IP del FortiGate
(no la del cliente interno). Opciones, de menos a más quirúrgica:

1. **SNAT en la policy/regla que cubre el hairpin** (cliente LAN → VIP-SOCL1):
   habilitar NAT (IP Pool o outgoing-interface) en la policy que matchea el tráfico interno hacia
   `200.41.220.53:443`, para que el origen quede como la IP del FGT en la subred del backend.

2. **Split-DNS interno (alternativa sin tocar NAT):** que la resolución interna de
   `socl1.grupoalemana.com` apunte directo al backend en vez de salir al público. *Pero* hoy el backend
   sirve **HTTP plano en :8000** (el TLS lo termina el FGT), así que esta vía requeriría además resolver
   cómo presentar el cert/HTTPS internamente → más trabajo. **Preferir la opción 1.**

> Nota: el ítem está catalogado como "hairpin para approvers internos" en los pendientes del SOC-L1.
> No bloquea operación: los approvers pueden aprobar desde el celular en datos móviles mientras tanto.

---

## Cómo verificar después del cambio

Desde un equipo **en la LAN** (no el propio backend, para no re-disparar el martian por loopback):

```bash
curl -m 15 -o /dev/null -w "HTTP %{http_code}\n" https://socl1.grupoalemana.com/health
# Esperado tras el fix: 200 (hoy: 504)
```

Y en el backend, confirmar que ahora el SYN llega con **origen = IP del FortiGate** (no `192.168.38.60`):

```bash
sudo timeout 20 tcpdump -nni eth0 'tcp port 8000 and not host 127.0.0.1'
# Esperado: SYN desde 192.168.32.1 (u otra IP del FGT) → con SYN-ACK de vuelta
```
