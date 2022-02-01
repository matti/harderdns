#!/usr/bin/env bash
set -euo pipefail

echo "whoami: $(whoami)"

(
  exec harderdns 1.1.1.1:53 8.8.8.8:53
) &

while true; do
  >/dev/null dig @localhost microsoft.com || true

  sleep 1
done

exec tail -f /dev/null