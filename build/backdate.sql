-- Age the freshly made demo data: each asset has been watched for some days,
-- people triaged its findings a few days ago, and the head-office firewall was
-- upgraded ten days ago. Run once on the build database, after curate.py and
-- before the dump; the demo itself then moves every date forward to its own
-- start (see ../seed/README.md).
--
-- The SLA defaults (critical 24 h, high 7 d, medium 30 d, low 90 d, KEV 6 h)
-- make the ages below show every SLA state somewhere.

BEGIN;

CREATE TEMP TABLE ages (hostname text PRIMARY KEY, days int NOT NULL) ON COMMIT DROP;
INSERT INTO ages VALUES
  ('debian-proxy-01', 120),             -- left alone: even the low findings are overdue
  ('rhel-app-01', 75),
  ('fw-branch-01', 60),
  ('fw-hq-01', 60),
  ('nginx:1.25.3', 40),
  ('ubuntu-web-01', 26),                -- medium findings due within days
  ('python:3.9.18-slim-bookworm', 12),
  ('win-dc-01', 5);                     -- its CVEs were published on 10 November

CREATE TEMP TABLE asset_age ON COMMIT DROP AS
  SELECT a.id, g.days * interval '1 day' AS age, a.hostname = 'fw-hq-01' AS upgraded
  FROM "Asset" a JOIN ages g ON g.hostname = a.hostname;

DO $$ BEGIN
  IF (SELECT count(*) FROM asset_age) <> (SELECT count(*) FROM "Asset") THEN
    RAISE EXCEPTION 'an asset has no age in this script';
  END IF;
END $$;

-- Detection: the asset, its findings and their due dates, the scan's own events.
UPDATE "Asset" a SET "createdAt" = a."createdAt" - x.age FROM asset_age x WHERE x.id = a.id;
UPDATE "Alert" al SET "detectedAt" = al."detectedAt" - x.age, "dueDate" = al."dueDate" - x.age
  FROM asset_age x WHERE x.id = al."assetId";
UPDATE "AlertEvent" e SET "createdAt" = e."createdAt" - x.age
  FROM "Alert" al JOIN asset_age x ON x.id = al."assetId"
  WHERE al.id = e."alertId" AND e.type IN ('detected', 'severity_changed');

-- Every scan but the latest of each asset happened back then too.
UPDATE "ScanJob" s SET "createdAt" = s."createdAt" - x.age, "startedAt" = s."startedAt" - x.age,
  "completedAt" = s."completedAt" - x.age
  FROM asset_age x
  WHERE x.id = s."assetId"
    AND s.id <> (SELECT id FROM "ScanJob" l WHERE l."assetId" = s."assetId" ORDER BY l."createdAt" DESC LIMIT 1);

-- Triage: three days ago; the firewall upgrade and what it resolved: ten days ago.
UPDATE "AlertEvent" e
  SET "createdAt" = e."createdAt" - CASE WHEN x.upgraded THEN interval '10 days' ELSE interval '3 days' END
  FROM "Alert" al JOIN asset_age x ON x.id = al."assetId"
  WHERE al.id = e."alertId" AND e.type IN ('status_changed', 'vex_justification_set', 'package_changed');
UPDATE "Alert" al SET "resolvedAt" = al."resolvedAt" - interval '10 days'
  FROM asset_age x WHERE x.id = al."assetId" AND x.upgraded AND al."resolvedAt" IS NOT NULL;
UPDATE "Alert" al SET "updatedAt" = greatest(al."detectedAt", coalesce(
  (SELECT max(e."createdAt") FROM "AlertEvent" e WHERE e."alertId" = al.id), al."detectedAt"));

-- The audit log: imports and scans when they happened; the build's sign-ins are not history.
UPDATE "AuditLog" l SET "createdAt" = l."createdAt" - g.days * interval '1 day'
  FROM ages g WHERE g.hostname = l.target AND l.action = 'asset_imported';
UPDATE "AuditLog" l SET "createdAt" = l."createdAt" - interval '60 days' WHERE l.action = 'asset_bulk_import';
UPDATE "AuditLog" l SET "createdAt" = l."createdAt" - g.days * interval '1 day'
  FROM ages g
  WHERE g.hostname = l.target AND l.action = 'asset_scanned'
    AND l.id <> (SELECT id FROM "AuditLog" m WHERE m.action = 'asset_scanned' AND m.target = l.target
                 ORDER BY m."createdAt" DESC LIMIT 1);
DELETE FROM "AuditLog" WHERE action = 'login';

-- The build's own access token is not part of the demo.
DELETE FROM "ApiToken";

COMMIT;
