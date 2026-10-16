
import os
import sys
import shutil
import subprocess
from pathlib import Path

port = os.environ.get("SERVER_PORT", os.environ.get("PORT", "8080"))
web_port = os.environ.get("WEB_PORT", "8081")
web_host = os.environ.get("WEB_HOST", "127.0.0.1")

# Use a Railway Volume for persistent certificates, if configured.
confdir = Path(
    os.environ.get("MITM_CONFIG_DIR", "/tmp/mitmproxy")
)
confdir.mkdir(parents=True, exist_ok=True)

mitmweb_path = shutil.which("mitmweb")

cmd = [
    mitmweb_path or sys.executable,
    *([] if mitmweb_path else ["-m", "mitmproxy.tools.main"]),
    "-s", "script.py",
    "-p", str(port),
    "--web-port", str(web_port),
    "--web-host", str(web_host),
    "--set", f"confdir={confdir}",
    "--no-web-open-browser",
]

print(f"[*] Certificate/config directory: {confdir}", flush=True)
print(f"[*] Starting mitmweb on port {port}...", flush=True)
print(f"[*] Web UI bind address: {web_host}:{web_port}", flush=True)

try:
    subprocess.run(cmd, check=True)
except FileNotFoundError as exc:
    print(f"[-] mitmweb executable not found: {exc}", flush=True)
    sys.exit(1)
except subprocess.CalledProcessError as exc:
    print(f"[-] mitmweb exited with code {exc.returncode}", flush=True)
    sys.exit(exc.returncode)
