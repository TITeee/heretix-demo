#!/usr/bin/env bash
# Write the demo's seed from the build instance (after curate.py and backdate.sql):
#
#   seed/heretix-management.sql.gz   the build's heretix-management database
#   seed/heretix-api.sql.gz          the part of a full heretix-api its alerts need
#
# Each ends by recording when it was made, in a table demo_seed that the demo's
# shift-dates scripts read on first start to bring every date up to that day.
#
#   build/make-seed.sh        (the build stack up; a full heretix-api reachable as PSQL)
set -euo pipefail
cd "$(dirname "$0")"

DEMO_EMAIL=admin@example.com
DEMO_PASSWORD=try-heretix-demo   # printed in the README: the demo runs on 127.0.0.1 only

q() { docker compose exec -T db psql -U postgres -d heretix_management -v ON_ERROR_STOP=1 -Atc "$1"; }
built_at=$(q "SELECT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')")
stamp="CREATE TABLE public.demo_seed AS SELECT timestamp '$built_at' AS built_at;"

mkdir -p work ../seed
q 'SELECT DISTINCT "externalId" FROM "Alert"' >work/ids.txt
q 'SELECT name FROM "Package" UNION SELECT "sourcePackage" FROM "Package" WHERE "sourcePackage" IS NOT NULL' >work/packages.txt
q "SELECT DISTINCT ecosystem FROM \"Alert\" WHERE ecosystem <> 'advisory'" >work/ecosystems.txt
echo "scope: $(wc -l <work/ids.txt) IDs, $(wc -l <work/packages.txt) package names, $(wc -l <work/ecosystems.txt) ecosystems" >&2

../scripts/export-api-subset.sh work work/heretix-api.sql.gz
{ gzip -dc work/heretix-api.sql.gz; echo "$stamp"; } | gzip -9 >../seed/heretix-api.sql.gz

# The demo's sign-in. bcryptjs from the heretix-management checkout the app was built from.
hash=$(cd "${MANAGEMENT_SRC:-../../heretix-management}" &&
  node -e 'console.log(require("bcryptjs").hashSync(process.argv[1], 12))' "$DEMO_PASSWORD")
q "UPDATE \"User\" SET password = '$hash' WHERE email = '$DEMO_EMAIL'" >/dev/null

{
  docker compose exec -T db pg_dump -U postgres --no-owner --no-privileges heretix_management
  echo "$stamp"
} | gzip -9 >../seed/heretix-management.sql.gz

ls -lh ../seed/*.sql.gz >&2
echo "built at $built_at UTC" >&2
