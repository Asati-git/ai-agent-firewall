#!/bin/bash
# Cerberus engine launcher for macOS / Linux.
# macOS: double-click in Finder (opens Terminal) — needs `chmod +x start-engine.command` once.
# Any shell: ./start-engine.command
cd "$(dirname "$0")" || exit 1
echo
echo "  Cerberus engine  -  http://127.0.0.1:9000/"
echo "  Press Ctrl+C (or close this window) to stop the engine."
echo
exec node ./bin/cerberus.mjs engine
