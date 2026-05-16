# Deploy en el server Wazuh (soc-l1)

Guía para clonar y correr `soc-l1` en el server productivo (mismo host donde corre Wazuh + el ex-n8n).

## Pre-requisitos en el server

```bash
# 1) git (probablemente ya está)
sudo apt-get install -y git

# 2) Python 3.12+ (Ubuntu 22.04 trae 3.10 por default - hay que agregar PPA o usar deadsnakes)
sudo apt-get install -y software-properties-common
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt-get update
sudo apt-get install -y python3.12 python3.12-venv python3.12-dev

# 3) uv (gestor moderno de Python, lo usamos para venv + install)
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## 1. Clonar el repo

El repo es **privado** en `github.com/safernandez666/soc-l1`. Dos formas de cloneo:

### Opción A: deploy key (recomendado para servers)

```bash
# 1) Generar par de keys en el server (sin passphrase para no requerir intervención humana)
ssh-keygen -t ed25519 -C "soc-l1-deploy@$(hostname)" -f ~/.ssh/soc-l1-deploy -N ""

# 2) Copiar la PUBLIC key
cat ~/.ssh/soc-l1-deploy.pub
```

En GitHub:
- Vas a `https://github.com/safernandez666/soc-l1/settings/keys`
- **Add deploy key**, pegás la pub key, name `wazuh-server`, allow write access **NO** (read-only deploy key)

```bash
# 3) Configurar SSH para usar esa key con github
cat >> ~/.ssh/config <<'EOF'

Host github-soc-l1
  HostName github.com
  User git
  IdentityFile ~/.ssh/soc-l1-deploy
  IdentitiesOnly yes
EOF

# 4) Clone usando el alias
cd /opt
sudo mkdir -p /opt/soc-l1
sudo chown $USER:$USER /opt/soc-l1
git clone git@github-soc-l1:safernandez666/soc-l1.git /opt/soc-l1
cd /opt/soc-l1
```

### Opción B: GitHub Personal Access Token (más simple, menos seguro)

```bash
# Crear PAT en https://github.com/settings/tokens/new (scope: repo)
git clone https://safernandez666:<TOKEN>@github.com/safernandez666/soc-l1.git /opt/soc-l1
# WARNING: el token queda en .git/config en plaintext
```

## 2. Configurar `.env` en el server

```bash
cd /opt/soc-l1
cp .env.example .env
nano .env
```

Llená al menos:
- `LDAP_BIND_PASSWORD` ← copiá de `sudo cat /root/.ad_wazuh_credentials` (extraído limpio con SCP+TextEdit en el flujo previo)
- El resto se completa cuando vayamos agregando agents/FastAPI/SMTP

Permisos:
```bash
chmod 600 .env
```

## 3. Crear venv e instalar

```bash
cd /opt/soc-l1
uv venv --python 3.12
source .venv/bin/activate
uv pip install -e ".[dev]"
```

## 4. Validar contra el AD productivo

Con el `.env` configurado, corré los tests primero:

```bash
.venv/bin/pytest -q
```

Si los 14 pasan (mock-based, no tocan AD), agregamos un test de integración real:

```bash
# Test con AD real - solo si los unit tests pasaron
python3 -c "
from src.config import LdapConfig
from src.tools.ldap import search_user
cfg = LdapConfig()  # lee del .env
user = search_user(cfg, 'wazuhseg')
print(user.model_dump_json(indent=2))
"
```

Debería imprimir el JSON del user `wazuhseg` con `account_enabled: true`. Si funciona, el LDAP module está validado end-to-end contra producción.

## 5. Actualizaciones futuras

Cada vez que pushees nuevo código:

```bash
cd /opt/soc-l1
git pull
.venv/bin/pytest -q   # asegurate que sigue verde
# (cuando tengamos Dockerfile: docker compose up -d --build)
```

## 6. Correr el servicio (FastAPI)

Ya tenés el webhook listo. Para levantarlo en foreground:

```bash
cd /opt/soc-l1
source .venv/bin/activate
uvicorn src.main:app --host 0.0.0.0 --port 8000 --log-level info
```

Test rápido:

```bash
# En otra terminal del server
curl http://localhost:8000/health
# → {"status":"ok","service":"soc-l1"}
```

### Test del webhook con HMAC

```bash
# Generar firma de un payload de prueba
BODY='{"agent":{"name":"test"},"data":{"srcip":"1.2.3.4"},"rule":{"id":"100","level":5,"description":"test","groups":["test"]},"id":"smoke-001","timestamp":"2026-05-16T12:00:00Z"}'
SECRET=$(grep '^WAZUH_WEBHOOK_SECRET=' .env | cut -d= -f2-)
SIG="sha256=$(echo -n "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $2}')"

curl -X POST http://localhost:8000/webhook/wazuh-alert \
  -H "Content-Type: application/json" \
  -H "X-Wazuh-Signature: $SIG" \
  -d "$BODY"
# → {"status":"accepted","alert_id":"smoke-001","source":"wazuh_native"}
```

### Apuntar el integrator Wazuh al nuevo endpoint

En `/var/ossec/etc/ossec.conf`:

```xml
<integration>
  <name>custom-n8n</name>  <!-- el script ya está en /var/ossec/integrations/custom-n8n -->
  <hook_url>http://localhost:8000/webhook/wazuh-alert</hook_url>
  <api_key>EL_VALOR_DE_WAZUH_WEBHOOK_SECRET</api_key>
  <level>5</level>
  <alert_format>json</alert_format>
</integration>
```

Reiniciar: `sudo systemctl restart wazuh-manager`

> El integrator `custom-n8n` que armaste antes sigue funcionando idéntico — solo cambia la URL del hook.

### Próximo: levantarlo persistente

Cuando esté validado con curl + alerta real, vamos a agregar:
- `Dockerfile` + `docker-compose.yml` (para que el servicio sea un container al lado del Wazuh)
- Systemd unit alternativo si preferís no usar Docker

Por ahora con uvicorn en foreground (o un `nohup`) alcanza para validar.

## Checklist post-deploy

- [ ] `git clone` exitoso (con deploy key o token)
- [ ] `.env` creado con `LDAP_BIND_PASSWORD` correcta y permisos `600`
- [ ] `uv venv && uv pip install -e ".[dev]"` sin errores
- [ ] `pytest -q` → 14 passed
- [ ] Test de integración LDAP imprime el user `wazuhseg`
- [ ] Antes de operar productivo: rotar el `LDAP_BIND_PASSWORD` a algo automation-friendly (sin chars problemáticos) y actualizar tanto en AD como en `/opt/soc-l1/.env`
