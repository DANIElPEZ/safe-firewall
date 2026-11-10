
# SafeWeb Firewall

Sistema de bloqueo de dominios web desarrollado en Python mediante Flask, SQLite y filtrado DNS.

## Instalación

**1. Clonar el repositorio:**

```bash
git clone URL_DEL_REPOSITORIO
cd SafeWeb_Firewall
```

**2. Crear y activar el entorno virtual:**

```powershell
python -m venv .venv
Set-ExecutionPolicy -Scope Process Bypass
.\.venv\Scripts\Activate.ps1
```

**3. Instalar dependencias:**

```powershell
pip install -r requirements.txt
pip install dnslib
```

## Configuración del DNS

Abrir PowerShell como administrador y ejecutar:

```powershell
netsh interface ipv4 set dnsservers name="Wi-Fi" static 127.0.0.1 primary
ipconfig /flushdns
```

## Ejecución

Se necesitan dos ventanas de PowerShell.

**Terminal 1 – Filtro DNS:**

```powershell
.\.venv\Scripts\Activate.ps1
python dns_filter.py
```

**Terminal 2 – Aplicación web:**

```powershell
.\.venv\Scripts\Activate.ps1
python app.py
```

Abrir en el navegador:

`http://127.0.0.1:3000`

## Restaurar DNS

Para volver a la configuración automática de Windows:

```powershell
netsh interface ipv4 set dnsservers name="Wi-Fi" source=dhcp
ipconfig /flushdns
```

## Tecnologías

- Python
- Flask
- SQLite
- dnslib
- HTML y CSS
- Windows DNS

**Nota:** El filtro DNS (`dns_filter.py`) debe permanecer activo para mantener los bloqueos. El uso de VPN o DNS seguro puede evitar el filtrado si no se configura protección adicional.
