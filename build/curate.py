#!/usr/bin/env python3
"""Make the freshly scanned demo data look like a fleet someone works on: tags,
findings in progress with comments, ignored ones with their reasons, and a
firewall upgraded so the scan closes what the upgrade fixed.

Goes through heretix-management's own API, so the alert history and the audit
log are what the app itself writes. Dates are moved afterwards (shift-dates).

  build/curate.py        (signed in with ./login.sh; the scan token in ./.token)
"""
import json, pathlib, subprocess, urllib.request

HERE = pathlib.Path(__file__).parent
BASE = "http://127.0.0.1:3200"

# curl writes the session cookie as "#HttpOnly_<domain> ...", a line that
# http.cookiejar reads as a comment, so the file is read here.
COOKIE = "; ".join(
    f"{f[5]}={f[6]}" for f in (line.removeprefix("#HttpOnly_").split("\t")
                               for line in (HERE / "cookies.txt").read_text().splitlines())
    if len(f) == 7 and not f[0].startswith("#"))
TOKEN = (HERE / ".token").read_text().strip()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect here is to the sign-in page: fail instead of following it."""
    def redirect_request(self, *args, **kwargs):
        return None


opener = urllib.request.build_opener(NoRedirect)


def sql(query):
    out = subprocess.run(
        ["docker", "compose", "exec", "-T", "db", "psql", "-U", "postgres", "-d", "heretix_management", "-Atc", query],
        capture_output=True, text=True, cwd=HERE, check=True).stdout
    return [line.split("|") for line in out.splitlines() if line]


def call(method, path, body=None, token=False):
    req = urllib.request.Request(BASE + path, method=method,
                                 data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {TOKEN}")
    else:
        req.add_header("Cookie", COOKIE)
    with opener.open(req, timeout=900) as r:
        return json.loads(r.read() or b"null")


def asset_id(hostname):
    return sql(f"SELECT id FROM \"Asset\" WHERE hostname = '{hostname}'")[0][0]


def alerts(where):
    return [r[0] for r in sql(
        'SELECT al.id FROM "Alert" al JOIN "Asset" a ON a.id = al."assetId" '
        f"WHERE al.status = 'open' AND {where} ORDER BY al.id")]


def patch(ids, body, label):
    for i in ids:
        call("PATCH", f"/api/alerts/{i}", body)
    print(f"{label}: {len(ids)}")


# 1. Asset tags.
tags = {name: tid for tid, name in sql('SELECT id, name FROM "Tag" WHERE type = \'asset\'')}
for host, names in {
    "fw-hq-01": ["Internet Facing", "Mission Critical"],
    "fw-branch-01": ["Internet Facing"],
    "ubuntu-web-01": ["Internet Facing"],
    "debian-proxy-01": ["Internet Facing"],
    "rhel-app-01": ["Mission Critical"],
    "win-dc-01": ["Mission Critical"],
}.items():
    call("POST", f"/api/assets/{asset_id(host)}/tags", {"add": [tags[n] for n in names], "remove": []})
print("tags: done")

# 2. The head-office firewall was upgraded; its scan closes what 7.4.9 fixed.
# The version is edited on the package, as on the asset's Packages tab (a CSV
# re-import would add a second FortiOS package instead of replacing it).
fw = asset_id("fw-hq-01")
pkg = sql(f"SELECT id FROM \"Package\" WHERE \"assetId\" = '{fw}' AND name = 'FortiOS'")[0][0]
call("PATCH", f"/api/assets/{fw}/packages/{pkg}", {"name": "FortiOS", "version": "7.4.9", "ecosystem": "advisory"})
scan = call("POST", f"/api/assets/{fw}/scan", token=True)
print(f"fw-hq-01 upgraded to 7.4.9: {scan}")

# 3. Being worked on.
patch(alerts("a.hostname = 'rhel-app-01' AND al.\"externalId\" IN ('CVE-2021-44228', 'CVE-2021-45046') AND al.\"packageName\" = 'org.apache.logging.log4j:log4j-core'"),
      {"status": "in_progress", "comment": "billing-app still ships log4j 2.14.1. Upgrade to 2.25.4 is in the next release; "
       "until then the JVM runs with -Dlog4j2.formatMsgNoLookups=true."},
      "log4j in progress")
patch(alerts("a.hostname = 'rhel-app-01' AND al.\"packageName\" = 'org.apache.commons:commons-text'"),
      {"status": "in_progress", "comment": "Ships with billing-app. Bumping to 1.10.0 together with the log4j upgrade."},
      "commons-text in progress")
patch(alerts("a.hostname = 'fw-branch-01' AND al.\"isKev\""),
      {"status": "in_progress", "comment": "Known exploited. Upgrade to 7.2.12 is booked for the branch maintenance window."},
      "fw-branch-01 KEV in progress")
patch(alerts("a.hostname = 'ubuntu-web-01' AND al.\"packageName\" IN ('express', 'axios', 'lodash')"),
      {"status": "in_progress", "comment": "shop-web dependency update is open as a pull request."},
      "shop-web deps in progress")

# 4. Ignored, each for its reason.
patch(alerts("a.hostname = 'debian-proxy-01' AND al.\"packageName\" LIKE 'samba%'"),
      {"status": "ignored", "ignoreReason": "not_affected", "vexJustification": "code_not_reachable",
       "comment": "Samba is installed but smbd and nmbd are disabled; nothing loads it (see the Services tab)."},
      "samba not affected")
patch(alerts("a.hostname = 'rhel-app-01' AND al.\"packageName\" LIKE 'mariadb%'"),
      {"status": "ignored", "ignoreReason": "not_affected", "vexJustification": "code_not_reachable",
       "comment": "Left over from the image; mariadb.service is not running. Removal is planned."},
      "mariadb not affected")
patch(alerts("a.hostname = 'python:3.9.18-slim-bookworm' AND al.severity = 'LOW'"),
      {"status": "ignored", "ignoreReason": "accepted_risk",
       "comment": "Low findings in the base image are accepted until the monthly rebuild."},
      "python image low accepted")
