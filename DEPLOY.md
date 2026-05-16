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

## 6. Cuando agreguemos el FastAPI service

Vamos a sumar:
- `Dockerfile` + `docker-compose.yml`
- Reemplazar el integrator de Wazuh para apuntar a `http://localhost:8000/webhook/wazuh-alert` (en vez del viejo n8n en 5678)
- Systemd unit o docker compose para que arranque solo

Por ahora solo tenés: normalize + LDAP tools + tests. Suficiente para validar la base.

## Checklist post-deploy

- [ ] `git clone` exitoso (con deploy key o token)
- [ ] `.env` creado con `LDAP_BIND_PASSWORD` correcta y permisos `600`
- [ ] `uv venv && uv pip install -e ".[dev]"` sin errores
- [ ] `pytest -q` → 14 passed
- [ ] Test de integración LDAP imprime el user `wazuhseg`
- [ ] Antes de operar productivo: rotar el `LDAP_BIND_PASSWORD` a algo automation-friendly (sin chars problemáticos) y actualizar tanto en AD como en `/opt/soc-l1/.env`
