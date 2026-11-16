#!/usr/bin/env bash
# Sign in to the build instance as admin; the session cookie goes to ./cookies.txt.
set -euo pipefail
cd "$(dirname "$0")"
rm -f cookies.txt
csrf=$(curl -s -c cookies.txt http://127.0.0.1:3200/api/auth/csrf | python3 -c 'import json,sys; print(json.load(sys.stdin)["csrfToken"])')
curl -s -b cookies.txt -c cookies.txt -o /dev/null -X POST http://127.0.0.1:3200/api/auth/callback/credentials \
  --data-urlencode "csrfToken=$csrf" --data-urlencode "email=admin@example.com" \
  --data-urlencode "password=$(cat .adminpw)" --data-urlencode "json=true"
grep -q session-token cookies.txt && echo "signed in"
