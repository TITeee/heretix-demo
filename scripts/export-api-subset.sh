#!/usr/bin/env bash
# Write a heretix-api database that holds only what the demo's alerts need, as
# one SQL file that a fresh PostgreSQL loads on its first start.
#
#   scripts/export-api-subset.sh <scope-dir> <out.sql.gz>
#
# <scope-dir> holds three lists, one entry per line, taken from the demo's
# heretix-management database (build/make-seed.sh writes them):
#   ids.txt         the externalId of every alert (CVE, OSV or vendor advisory ID)
#   packages.txt    every package name and source package name on the demo's assets
#   ecosystems.txt  the OSV ecosystems of the demo's alerts (Debian:12, npm, ...)
#
# Reads from a full heretix-api database and never writes to it: everything
# runs in one read-only transaction. PSQL is how to reach that database, by
# default the heretix-api Compose project's:
#
#   PSQL="docker exec -i heretix-api-db-1 psql -U postgres -d heretix"
#
# The output holds:
#   - the schema and the migration history, so the api's `prisma migrate deploy`
#     finds nothing to do;
#   - the vulnerabilities and every source record under them (NVD, OSV, vendor
#     advisories, CNA);
#   - of their affected packages and products, the ones on the demo's assets:
#     an Ubuntu kernel CVE alone lists every Ubuntu release and dozens of kernel
#     flavours with hundreds of versions each, and Red Hat lists RHEL 8, 9 and 10;
#   - the Debian and Ubuntu tracker statuses and the Debian binary-to-source map
#     of the demo's packages;
#   - the last completed job of each source, so the api reports its data as loaded;
#   - every collection job disabled, so the demo never fetches anything.
#
# Vendor advisories keep an empty rawData for Red Hat and Microsoft: neither
# heretix-api's search nor heretix-management's pages read it, and it is most of
# their size.
set -euo pipefail

scope=${1:?usage: export-api-subset.sh <scope-dir> <out.sql.gz>}
out=${2:?usage: export-api-subset.sh <scope-dir> <out.sql.gz>}
PSQL=${PSQL:-docker exec -i heretix-api-db-1 psql -U postgres -d heretix}
PG_DUMP=${PG_DUMP:-${PSQL/psql/pg_dump}}

for f in ids packages ecosystems; do
  [ -s "$scope/$f.txt" ] || { echo "missing or empty: $scope/$f.txt" >&2; exit 1; }
done

# A list file as a psql variable holding a quoted text[] literal: {"a","b",...}
array_var() {
  printf '\\set %s '"'"'{%s}'"'"'\n' "$1" \
    "$(grep -v '^[[:space:]]*$' "$scope/$2.txt" | sort -u | sed 's/["\\]/\\&/g; s/.*/"&"/' | paste -sd, -)"
}

# The sets, as SQL fragments over the psql variables :ids, :pkgs and :ecos.
# Fragments rather than temporary tables, which a read-only transaction cannot create.
IDS=":'ids'::text[]"
PKGS=":'pkgs'::text[]"
ECOS=":'ecos'::text[]"
V="SELECT id FROM \"Vulnerability\" WHERE \"cveId\" = ANY($IDS) OR \"osvId\" = ANY($IDS) OR \"advisoryId\" = ANY($IDS)"
NVD="SELECT id FROM \"NVDVulnerability\" WHERE \"masterVulnId\" IN ($V) OR \"cveId\" = ANY($IDS)"
OSV="SELECT id FROM \"OSVVulnerability\" WHERE \"masterVulnId\" IN ($V) OR \"osvId\" = ANY($IDS) OR \"cveId\" = ANY($IDS)"
ADV="SELECT id FROM \"AdvisoryVulnerability\" WHERE \"masterVulnId\" IN ($V) OR \"externalId\" = ANY($IDS) OR \"cveId\" = ANY($IDS)"
CNA="SELECT id FROM \"CnaVulnerability\" WHERE \"masterVulnId\" IN ($V) OR \"cveId\" = ANY($IDS)"
# Red Hat's vendor names for the RHEL releases in :ecos ("Red Hat:9" is red-hat-9).
RH_VENDORS="SELECT 'red-hat-' || split_part(e, ':', 2) FROM unnest($ECOS) e WHERE e LIKE 'Red Hat:%'"

# OSV's own list of affected packages, cut to the demo's ecosystems and packages.
OSV_AFFECTED="(SELECT coalesce(jsonb_agg(a), '[]'::jsonb) FROM jsonb_array_elements(t.\"rawData\"->'affected') a
  WHERE a->'package'->>'ecosystem' = ANY($ECOS) AND a->'package'->>'name' = ANY($PKGS))"

# Tables copied, each with the rows to take, in table column order
# (jsonb_populate_record replaces one column and keeps the others in place).
tables=(
  "Vulnerability|SELECT t.* FROM \"Vulnerability\" t WHERE t.id IN ($V)"
  "NVDVulnerability|SELECT t.* FROM \"NVDVulnerability\" t WHERE t.id IN ($NVD)"
  "NVDAffectedPackage|SELECT t.* FROM \"NVDAffectedPackage\" t WHERE t.\"vulnerabilityId\" IN ($NVD)"
  "OSVVulnerability|SELECT (jsonb_populate_record(t, jsonb_build_object('rawData',
     CASE WHEN jsonb_typeof(t.\"rawData\"->'affected') = 'array'
          THEN jsonb_set(t.\"rawData\", '{affected}', $OSV_AFFECTED) ELSE t.\"rawData\" END))).*
   FROM \"OSVVulnerability\" t WHERE t.id IN ($OSV)"
  "OSVAffectedPackage|SELECT t.* FROM \"OSVAffectedPackage\" t WHERE t.\"vulnerabilityId\" IN ($OSV)
   AND t.ecosystem = ANY($ECOS) AND t.\"packageName\" = ANY($PKGS)"
  "AdvisoryVulnerability|SELECT (jsonb_populate_record(t, jsonb_build_object('rawData',
     CASE WHEN t.source IN ('red-hat', 'red-hat-vex', 'advisory-microsoft') THEN '{}'::jsonb ELSE t.\"rawData\" END))).*
   FROM \"AdvisoryVulnerability\" t WHERE t.id IN ($ADV)"
  "AdvisoryAffectedProduct|SELECT t.* FROM \"AdvisoryAffectedProduct\" t JOIN \"AdvisoryVulnerability\" v ON v.id = t.\"advisoryId\"
   WHERE t.\"advisoryId\" IN ($ADV) AND CASE
     WHEN v.source IN ('red-hat', 'red-hat-vex') THEN t.vendor IN ($RH_VENDORS) AND t.product = ANY($PKGS)
     WHEN v.source = 'advisory-microsoft' THEN t.product = ANY($PKGS) OR t.product LIKE ANY (SELECT p || ' (%' FROM unnest($PKGS) p)
     ELSE true END"
  "CnaVulnerability|SELECT t.* FROM \"CnaVulnerability\" t WHERE t.id IN ($CNA)"
  "CnaAffectedProduct|SELECT t.* FROM \"CnaAffectedProduct\" t WHERE t.\"vulnerabilityId\" IN ($CNA)"
  "UbuntuTrackerStatus|SELECT t.* FROM \"UbuntuTrackerStatus\" t WHERE t.\"vulnId\" = ANY($IDS)
   AND t.ecosystem = ANY($ECOS) AND t.\"sourcePackage\" = ANY($PKGS)"
  "DebianTrackerStatus|SELECT t.* FROM \"DebianTrackerStatus\" t WHERE t.\"vulnId\" = ANY($IDS)
   AND t.ecosystem = ANY($ECOS) AND t.\"sourcePackage\" = ANY($PKGS)"
  "DebianSourcePackage|SELECT t.* FROM \"DebianSourcePackage\" t WHERE t.ecosystem = ANY($ECOS) AND t.\"binaryName\" = ANY($PKGS)"
  "CollectionJob|SELECT DISTINCT ON (t.source) t.* FROM \"CollectionJob\" t WHERE t.status = 'completed' ORDER BY t.source, t.\"completedAt\" DESC"
  "JobConfig|SELECT s.source, false, now() FROM (SELECT source FROM \"JobConfig\" UNION SELECT DISTINCT source FROM \"CollectionJob\" UNION SELECT unnest(ARRAY['nvd', 'kev', 'epss'])) s"
  "DataMigration|SELECT t.* FROM \"DataMigration\" t"
  "_prisma_migrations|SELECT t.* FROM \"_prisma_migrations\" t"
)

script() {
  array_var ids ids
  array_var pkgs packages
  array_var ecos ecosystems
  cat <<'SQL'
\set ON_ERROR_STOP on
BEGIN TRANSACTION READ ONLY;
SQL
  printf '\\o /dev/stderr\n'
  printf 'SELECT cardinality(%s) AS ids, (SELECT count(*) FROM (%s) x) AS vulns, (SELECT count(*) FROM (%s) x) AS nvd, (SELECT count(*) FROM (%s) x) AS osv, (SELECT count(*) FROM (%s) x) AS advisories, (SELECT count(*) FROM (%s) x) AS cna;\n' "$IDS" "$V" "$NVD" "$OSV" "$ADV" "$CNA"
  printf '\\o\n'
  for entry in "${tables[@]}"; do
    local table=${entry%%|*} query=${entry#*|}
    printf '\\echo '"'"'COPY public."%s" FROM stdin;'"'"'\n' "$table"
    printf 'COPY (%s) TO STDOUT;\n' "$(tr '\n' ' ' <<<"$query")"
    printf '\\echo '"'"'\\\\.'"'"'\n'
  done
  echo 'COMMIT;'
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "schema..." >&2
$PG_DUMP --schema-only --no-owner --no-privileges >"$tmp/schema.sql"

echo "data for $(grep -cv '^[[:space:]]*$' "$scope/ids.txt") IDs..." >&2
script | $PSQL -X -q -A -t -f - >"$tmp/data.sql"

{
  cat "$tmp/schema.sql"
  echo "SET session_replication_role = replica;" # load children before checking parents
  cat "$tmp/data.sql"
  echo "SET session_replication_role = origin;"
  echo "ANALYZE;"
} | gzip -9 >"$out"
echo "wrote $out ($(du -h "$out" | cut -f1))" >&2
