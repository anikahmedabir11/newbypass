import os
import sys
import shutil
import subprocess

port = os.environ.get('SERVER_PORT', os.environ.get('PORT', '8080'))
web_port = os.environ.get('WEB_PORT', '8081')
web_host = os.environ.get('WEB_HOST', '127.0.0.1')

# Find mitmweb in system PATH
mitmweb_path = shutil.which("mitmweb")

# If not found in PATH, fallback to common environments (e.g. Pterodactyl container)
if not mitmweb_path:
    for fallback in [
        "/home/container/.local/bin/mitmweb",
        os.path.expanduser("~/.local/bin/mitmweb")
    ]:
        if os.path.exists(fallback):
            mitmweb_path = fallback
            break

print(f"[*] Starting mitmweb proxy on port {port}...")
print(f"[*] Web UI available at: http://{web_host if web_host != '0.0.0.0' else '127.0.0.1'}:{web_port}")

cmd = [
    mitmweb_path if mitmweb_path else "mitmweb",
    "-s", "script.py",
    "-p", str(port),
    "--web-port", str(web_port),
    "--web-host", str(web_host),
    "--set", "block_global=false",
    "--no-web-open-browser"
]

try:
    subprocess.run(cmd)
except FileNotFoundError:
    try:
        # Fallback to direct python module execution
        from mitmproxy.tools.main import mitmweb
        sys.argv = [
            "mitmweb",
            "-s", "script.py",
            "-p", str(port),
            "--web-port", str(web_port),
            "--web-host", str(web_host),
            "--set", "block_global=false",
            "--no-web-open-browser"
        ]
        mitmweb()
    except Exception as e:
        print(f"[-] Error: mitmweb executable still not found. Make sure requirements.txt installed mitmproxy properly. Details: {e}")

