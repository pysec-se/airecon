#!/bin/bash
# AIRecon Sandbox Entrypoint
# Keeps the container alive for `docker exec` commands

echo "[airecon-sandbox] Container started."
echo "[airecon-sandbox] Tools ready at: $(date)"

# Chromium CDP server is started LAZILY by AIRecon when browser_action is
# first called.  Starting it here wasted 200-500 MB of RAM even when the
# browser tool was never used, reducing headroom for recon tools and
# contributing to OOM container crashes.
#
# To start Chromium manually for debugging:
#   docker exec airecon-sandbox-active chromium --headless=new --no-sandbox \
#     --disable-dev-shm-usage --disable-gpu --remote-debugging-port=9222 \
#     --remote-debugging-address=0.0.0.0 --disable-web-security \
#     --remote-allow-origins='*' --ignore-certificate-errors &
#echo "[airecon-sandbox] Starting Chromium CDP Server on port 9222..."
#chromium \
#    --headless=new \
#    --no-sandbox \
#    --disable-dev-shm-usage \
#    --disable-gpu \
#    --remote-debugging-port=9222 \
#    --remote-debugging-address=0.0.0.0 \
#    --disable-web-security \
#    --remote-allow-origins="*" \
#    --ignore-certificate-errors \
#    > /dev/null 2>&1 &

# Keep container alive
if [ -d "/workspace" ]; then
    sudo chown -R pentester:pentester /workspace 2>/dev/null || true
    sudo chmod -R 775 /workspace 2>/dev/null || true
    echo "[airecon-sandbox] Workspace permissions fixed."
fi

# Keep container alive
exec sleep infinity
