# heretix demo

Try **[heretix](https://titeee.github.io/heretix-web/)** on sample data in a few minutes: a small fleet of servers, container images and firewalls, already scanned and partly worked on, in your own browser. Nothing leaves your machine.

heretix is a self-hosted suite that tracks the vulnerabilities of servers, containers and network appliances in one inventory. This demo runs its two services, [heretix-management](https://github.com/TITeee/heretix-management) (the web console) and [heretix-api](https://github.com/TITeee/heretix-api) (the vulnerability data), with a database each.

## Run it

You need Docker with Docker Compose v2, about 2 GB of free memory and about 10 GB of free disk (the first start downloads the images).

```sh
git clone https://github.com/TITeee/heretix-demo.git
cd heretix-demo
docker compose up -d
```

The first start loads the sample data, which takes a minute or two. Then open **http://localhost:3000** and sign in:

- Email: `admin@example.com`
- Password: `try-heretix-demo`

Port 3000 taken? Run `DEMO_PORT=3300 docker compose up -d` and open http://localhost:3300 instead. The demo listens on 127.0.0.1 only.

## What is in it

| Asset | What it is |
|---|---|
| `rhel-app-01` | RHEL 9: PostgreSQL and a Java billing service with an old log4j; a newer kernel installed but not booted |
| `ubuntu-web-01` | Ubuntu 24.04, nine months behind: nginx in front of a Node.js shop and a Django API |
| `debian-proxy-01` | Debian 12, left mostly unpatched: HAProxy and BIND, Samba installed but never started |
| `win-dc-01` | Windows Server 2022 domain controller |
| `fw-hq-01`, `fw-branch-01` | FortiGate firewalls: the head office upgraded ten days ago, the branch still on an old FortiOS |
| `nginx:1.25.3`, `python:3.9.18-slim-bookworm` | Two old public container images |

The Linux hosts were real virtual machines, collected with [heretix-cli](https://github.com/TITeee/heretix-cli), so what runs on them is what heretix saw running. The dates move with the demo: whenever you start it, findings were detected weeks ago and triaged a few days ago.

## Where to look

1. **Dashboard**: what is overdue against its SLA, and the known-exploited (CISA KEV) findings first.
2. **An asset's Remediation tab**: alerts grouped by the update that fixes them, and the ones with no fix grouped by why. On `win-dc-01`, one update closes 553 findings. On `rhel-app-01`, 77,000 open findings sort into 30 updates (the kernel update alone covers about 1,500, five of them known exploited) and five groups the vendor has not fixed (deferred, will not fix, and so on).
3. **An asset's Services tab** (try `ubuntu-web-01`): which services run the vulnerable code, which need a restart after the last upgrade, and what is installed but never loaded.
4. **Alerts**: open Log4Shell (`CVE-2021-44228`) on `rhel-app-01`, in progress with a comment, and the Samba findings on `debian-proxy-01`, set aside as not affected, with their reason in the VEX export.
5. **`fw-hq-01`'s history**: the upgrade closed the findings it fixed on its own.

## What is turned off

The demo's vulnerability database holds only what the sample assets need, so anything that would show results for other software is turned off: importing SBOMs, scanning, adding or editing packages, and the daily refresh. Triage works: change statuses, comment, tag, export.

To try heretix on your own servers, install it as described in the [heretix documentation](https://titeee.github.io/heretix-web/docs/).

## Stop and reset

```sh
docker compose down        # stop; your changes stay
docker compose down -v     # stop and delete the data: the next start is fresh
```

## How the data is made

[build/](build/) holds the steps: scan the sample SBOMs in a heretix-management against a full heretix-api, triage and age the data, then take only the vulnerabilities those assets need from heretix-api. The two databases ship as images, `ghcr.io/titeee/heretix-demo-api-db` and `ghcr.io/titeee/heretix-demo-management-db`.

## License

Apache-2.0, as heretix itself.
