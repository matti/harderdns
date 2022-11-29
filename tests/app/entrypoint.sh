#!/usr/bin/env bash
set -euo pipefail

echo "whoami: $(whoami)"

(
  exec harderdns 1.1.1.1:53 9.9.9.9:53
) >/tmp/harderdns.log 2>&1 &

while true; do
  if >/dev/null dig @127.0.0.1 microsoft.com; then
    echo "ok"
  else
    echo "failed"
    tail -n 30 /tmp/harderdns.log
  fi
  sleep 1
done
