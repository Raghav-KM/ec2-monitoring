# ec2-monitoring

A small web page that shows what an EC2 machine is doing: CPU, RAM and disk I/O **per process**, plus total CPU,
memory, swap and disk usage. It is one Python file (`procmon.py`) with no dependencies, only the standard library.
It reads `/proc` when a page asks for it, so it uses no CPU while nobody is looking (about 20 MB of RAM).

The page shows CPU and memory with short history graphs, disk usage, and a sortable, filterable process table with
usage bars. Click the star next to a process to **pin** it: pinned processes stay in a table at the top, and a pin
that has no running process is shown as "not running", which makes it easy to spot a crashed service. Pins are
stored in the browser (localStorage) and follow the command line, so they survive restarts and new PIDs. A pinned process
is listed only in the Pinned table, not again in the main list. Press `/` to jump to the filter.

The refresh rate can go down to every 0.25 s. CPU % then moves in coarser steps, because Linux counts CPU time in
10 ms ticks (disk I/O and memory stay exact).

Linux only. Python 3.9 or newer.

## Run it locally

```bash
python3 procmon.py            # http://127.0.0.1:8080
```

| Variable | Default | |
|---|---|---|
| `HOST` | `127.0.0.1` | `0.0.0.0` to listen on all interfaces |
| `PORT` | `8080` | |
| `MONITOR_USER`, `MONITOR_PASS` | not set | turn on basic auth |

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Layout

```
procmon.py                          the server and the page
tests/test_smoke.py                 snapshot shape, basic auth, /healthz
deploy/procmon.service              systemd unit (port 8081, login from /etc/procmon.env)
deploy/nginx-procmon.conf           nginx server block for the public hostname
deploy/setup.sh                     one-time setup on the server
.github/workflows/deploy.yml        CI: test, then deploy to EC2
```

## Deployment

Every push to `main` runs the tests, copies `procmon.py` to `/opt/procmon` on the EC2 machine, installs
`deploy/procmon.service` if it changed, restarts the `procmon` service and checks `/healthz` on the machine itself.
If the check fails, the previous version is put back and the service restarted. Pull requests only run the tests.

It uses the same repository secrets as x86-compiler-java: `EC2_HOST`, `EC2_USER` and `EC2_SSH_KEY`. Optionally set
the repository **variable** `SITE_URL` (for example `https://monitor.projects-rkm.in`) to also check the public address
after a deploy.

The service listens on `127.0.0.1:8081` (x86c already uses 8080) and nginx passes the public hostname to it.

One-time setup on the server:

```bash
# 1. app folder, login and service
scp deploy/procmon.service deploy/setup.sh ec2-user@<host>:/tmp/
ssh ec2-user@<host> 'bash /tmp/setup.sh'          # prints the generated password once

# 2. nginx (point the hostname's DNS A record at the instance first, edit server_name in the file)
sudo cp nginx-procmon.conf /etc/nginx/conf.d/procmon.conf
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d monitor.projects-rkm.in   # adds TLS
```

Then push to `main`. The monitor asks for the login in `/etc/procmon.env` (`MONITOR_USER`, `MONITOR_PASS`); change
them there and run `sudo systemctl restart procmon`.

The service runs as `ec2-user` with only the `CAP_SYS_PTRACE` capability, which is what lets it read the disk I/O of
other users' processes without running as root.
