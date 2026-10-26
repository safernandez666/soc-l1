# Cómo correr la prueba de la API de Órdenes (Kong)

El script `probar_kong_ordenes.py` verifica el camino completo
**Internet → FortiGate → Kong → IIS (ERP)** de `https://gateway.grupoalemana.com`.

## Requisitos
- Python 3 (cualquier versión reciente). No hay que instalar nada más.
- Una red **externa**: 4G, red doméstica u otra fuera de Grupo Alemana. Desde la red interna o la VPN,
  `gateway.grupoalemana.com` resuelve a otro servicio y la prueba falla con un aviso (ver "Problemas comunes").
- La **apikey** que se les entregó por separado.
- Para la prueba de login: usuario, password y EmpresaId del ERP (opcional).

## Pasos
1. Guardar `probar_kong_ordenes.py` en una carpeta.
2. Abrir una terminal en esa carpeta y ejecutar:

   ```
   python3 probar_kong_ordenes.py --modo wan
   ```
   En Windows, si `python3` no existe, usar `python` o `py`.
3. Cuando lo pida, ingresar la apikey. No se ve mientras se escribe; es normal.
4. La prueba 5 pide usuario ERP, password y EmpresaId. Ver la nota de abajo antes de completarla.

Alternativa sin preguntas interactivas:

```
ORD_APIKEY=xxxx python3 probar_kong_ordenes.py --modo wan --sin-login
```

## Opciones
| Opción | Qué hace |
|---|---|
| `--modo wan` | Por Internet, con TLS verificado. Es la que hay que usar. |
| `--modo lan` | Directo a Kong dentro de la red interna (192.168.38.62:8443). Solo para el equipo de infraestructura. |
| `--sin-login` | Omite la prueba 5 (login real). |
| `--no-color` | Sin colores en la salida. |

Variables opcionales: `ORD_APIKEY`, `ORD_USER`, `ORD_PASS`.

## Nota sobre el login real
La prueba 5 hace un `POST /api/token` con un usuario real, y eso **queda registrado en el log del ERP**.
Avisar al responsable del ERP antes de correrla, o usar `--sin-login`.
La apikey y la password nunca se imprimen ni se guardan en disco.

## Cómo leer el resultado
- Termina con `TODO OK · 10 DE 10 PRUEBAS` y código de salida 0 si todo está bien.
- Con `--sin-login` son menos pruebas; todas deben figurar como `[ OK ]`.
- Si alguna falla, mostrar `esperado:` contra lo recibido. Enviar la salida completa (sin la apikey) a infraestructura.

## Problemas comunes
- **403 sin header `server`** en todas las pruebas: el firewall bloquea el User-Agent. El script ya manda uno propio.
  Si pasa al consumir desde otro sistema, configurar un `User-Agent` propio y fijo, por ejemplo `MiSistema/1.0`.
- **Aviso "la primera respuesta no es de Kong"**: se está corriendo desde la red interna o la VPN. Probar desde 4G.
- **`401` en la prueba 2 sin pasar a IIS**: la apikey es incorrecta o no está habilitada.
- **`429`**: se superó el límite de 300 requests por minuto. Esperar un minuto.
- **Timeout o error de conexión**: verificar que haya salida a Internet por el puerto 443.

## Qué verifica
1. Kong exige apikey (`401`) y el login no llega al backend sin ella.
2. Con apikey la request llega al IIS y respeta el límite de 300/min.
3. No hay rutas sobrantes: lo inexistente da `404`, no hay camino de escritura y el Admin API no se expone.
4. Latencia menor a 1 s con la conexión en caliente.
5. Login real y una lectura autenticada de datos (zonas), y un error de negocio que llega intacto.
