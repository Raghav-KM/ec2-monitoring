#!/usr/bin/env python3
"""procmon: single-file, zero-dependency Linux process monitor (CPU / RAM / disk I/O per process).

Reads /proc only when a page requests it, so idle cost is ~0.
Env: HOST (127.0.0.1), PORT (8080), MONITOR_USER / MONITOR_PASS (enable basic auth)
"""
import base64, hmac, json, os, pwd, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8080"))
AUTH = (os.environ.get("MONITOR_USER"), os.environ.get("MONITOR_PASS"))
TICK = os.sysconf("SC_CLK_TCK")
PAGE_SZ = os.sysconf("SC_PAGE_SIZE")
REAL_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "vfat", "ntfs", "fuseblk"}

_lock = Lock()
_prev = {"t": 0.0, "procs": {}, "cpu": None}
_cache = {"t": 0.0, "body": b"{}"}
_users = {}


def _read(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


def _user(uid):
    if uid not in _users:
        try:
            _users[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            _users[uid] = str(uid)
    return _users[uid]


def _meminfo():
    m = {}
    for line in _read("/proc/meminfo").decode().splitlines():
        k, v = line.split(":", 1)
        m[k] = int(v.split()[0]) * 1024
    return m


def _cpu_times():
    f = _read("/proc/stat").split(b"\n", 1)[0].split()[1:]
    v = [int(x) for x in f]
    return sum(v), v[3] + (v[4] if len(v) > 4 else 0)  # total, idle+iowait


def _disks():
    out, seen = [], set()
    for line in _read("/proc/mounts").decode().splitlines():
        dev, mnt, fs = line.split()[:3]
        if fs not in REAL_FS or dev in seen:
            continue
        seen.add(dev)
        try:
            s = os.statvfs(mnt)
        except OSError:
            continue
        total = s.f_blocks * s.f_frsize
        if total:
            out.append([mnt.replace("\\040", " "), (s.f_blocks - s.f_bfree) * s.f_frsize, total])
    return out


def snapshot():
    now = time.time()
    with _lock:
        if now - _cache["t"] < 0.8:           # many tabs -> one /proc scan
            return _cache["body"]
        dt = now - _prev["t"] if _prev["t"] else 0
        total, idle = _cpu_times()
        pc = _prev["cpu"]
        cpu_pct = 100.0 * (1 - (idle - pc[1]) / (total - pc[0])) if pc and total > pc[0] else 0.0

        procs, rows = {}, []
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            raw = _read(f"/proc/{name}/stat")
            if not raw:
                continue
            i = raw.rfind(b")")
            comm = raw[raw.find(b"(") + 1:i].decode(errors="replace")
            f = raw[i + 2:].split()
            ticks = int(f[11]) + int(f[12])
            start = f[19]
            rss = int(f[21]) * PAGE_SZ
            pid = int(name)
            io = _read(f"/proc/{name}/io")
            rd = wr = None
            if io:
                for l in io.split(b"\n"):
                    if l.startswith(b"read_bytes:"):
                        rd = int(l.split()[1])
                    elif l.startswith(b"write_bytes:"):
                        wr = int(l.split()[1])
            procs[pid] = (start, ticks, rd, wr)
            p = _prev["procs"].get(pid)
            cpu = rr = wrt = 0.0
            if p and p[0] == start and dt > 0:
                cpu = (ticks - p[1]) / TICK / dt * 100
                rr = (rd - p[2]) / dt if rd is not None and p[2] is not None else None
                wrt = (wr - p[3]) / dt if wr is not None and p[3] is not None else None
            elif rd is None:
                rr = wrt = None
            cmd = (_read(f"/proc/{name}/cmdline") or b"").replace(b"\0", b" ").decode(errors="replace").strip()
            try:
                uid = os.stat(f"/proc/{name}").st_uid
            except OSError:
                uid = 0
            rows.append([pid, comm, _user(uid), round(max(cpu, 0), 1), rss,
                         None if rr is None else max(0, int(rr)),
                         None if wrt is None else max(0, int(wrt)), int(f[17]), cmd[:200] or comm])

        mi = _meminfo()
        up = float(_read("/proc/uptime").split()[0])
        body = json.dumps({
            "ts": now, "cores": os.cpu_count(), "cpu": round(cpu_pct, 1),
            "mem": [mi["MemTotal"] - mi["MemAvailable"], mi["MemTotal"]],
            "swap": [mi["SwapTotal"] - mi["SwapFree"], mi["SwapTotal"]],
            "load": os.getloadavg(), "up": up, "disks": _disks(), "procs": rows,
        }, separators=(",", ":")).encode()
        _prev.update(t=now, procs=procs, cpu=(total, idle))
        _cache.update(t=now, body=body)
        return body


PAGE = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>procmon</title>
<style>
:root{color-scheme:light dark;--l:#8884}
body{font:14px/1.4 system-ui,sans-serif;margin:0;padding:14px;max-width:1200px;margin:auto}
#s{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;margin-bottom:12px}
.c{border:1px solid var(--l);border-radius:8px;padding:10px 12px}
.c b{display:block;font-size:11px;opacity:.6;text-transform:uppercase}
.c i{font-style:normal;font-size:22px;font-weight:600}.c small{display:block;opacity:.65}
.bar{height:5px;background:var(--l);border-radius:3px;margin-top:6px;overflow:hidden}
.bar span{display:block;height:100%;background:#3b82f6}.bar .w{background:#f59e0b}.bar .x{background:#ef4444}
.d{font-size:12px;margin-top:6px}.d div{display:flex;justify-content:space-between}
input{padding:6px 9px;border:1px solid var(--l);border-radius:6px;background:none;color:inherit;width:240px;margin-bottom:8px}
#w{overflow-x:auto;border:1px solid var(--l);border-radius:8px}
table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}
th,td{padding:5px 10px;text-align:right;white-space:nowrap;border-bottom:1px solid var(--l)}
th:first-child,td:first-child,th:nth-child(3),td:nth-child(3){text-align:left}
th{font-size:11px;text-transform:uppercase;opacity:.7;cursor:pointer}
td:first-child{max-width:240px;overflow:hidden;text-overflow:ellipsis}.h{color:#ef4444;font-weight:600}
</style>
<div id=s></div>
<input id=q placeholder="filter name / user / pid / cmd"> <small id=n></small>
<div id=w><table><thead id=h></thead><tbody id=b></tbody></table></div>
<script>
const C=[["Process",1,"s"],["PID",0,"n"],["User",2,"s"],["CPU %",3,"n"],["RAM",4,"n"],["Disk rd/s",5,"n"],["Disk wr/s",6,"n"],["Thr",7,"n"]];
let D,S=3,A=0;const $=i=>document.getElementById(i);
const B=n=>{if(n==null)return"-";let u="BKMGT",i=0;while(n>=1024&&i<4){n/=1024;i++}return(i?n.toFixed(1):n|0)+" "+u[i]+(i?"B":"")};
const E=s=>String(s).replace(/[&<>"]/g,c=>"&#"+c.charCodeAt(0)+";");
const cls=p=>p>=90?"x":p>=70?"w":"";
const card=(t,v,sub,p)=>`<div class=c><b>${t}</b><i>${v}</i><small>${sub}</small>${p==null?"":`<div class=bar><span class=${cls(p)} style=width:${Math.min(p,100)}%></span></div>`}</div>`;
function draw(){if(!D)return;
 const m=D.mem[0]/D.mem[1]*100,u=D.up,dk=D.disks.map(d=>`<div><span>${E(d[0])}</span><span>${B(d[1])} / ${B(d[2])}</span></div><div class=bar><span class=${cls(d[1]/d[2]*100)} style=width:${d[1]/d[2]*100}%></span></div>`).join("");
 $("s").innerHTML=card("CPU",D.cpu.toFixed(1)+"%",D.cores+" cores · load "+D.load.map(x=>x.toFixed(2)).join(" "),D.cpu)
  +card("Memory",m.toFixed(1)+"%",B(D.mem[0])+" / "+B(D.mem[1])+(D.swap[1]?" · swap "+B(D.swap[0]):""),m)
  +`<div class=c><b>Storage</b><div class=d>${dk||"-"}</div></div>`
  +card("System",D.procs.length+" procs","up "+(u/86400|0)+"d "+(u%86400/3600|0)+"h");
 const q=$("q").value.toLowerCase();let r=D.procs.filter(p=>!q||(p[1]+" "+p[2]+" "+p[0]+" "+p[8]).toLowerCase().includes(q));
 const k=C[S][1],t=C[S][2];r.sort((a,b)=>{let x=a[k],y=b[k];if(x==null)return 1;if(y==null)return-1;return(t=="s"?String(x).localeCompare(y):x-y)*(A?1:-1)});
 $("n").textContent=Math.min(r.length,60)+" of "+r.length;
 $("b").innerHTML=r.slice(0,60).map(p=>`<tr title="${E(p[8])}"><td>${E(p[1])}<td>${p[0]}<td>${E(p[2])}<td class="${p[3]>=80?"h":""}">${p[3].toFixed(1)}<td>${B(p[4])}<td>${B(p[5])}<td>${B(p[6])}<td>${p[7]}`).join("")}
$("h").innerHTML="<tr>"+C.map((c,i)=>`<th data-i=${i}>${c[0]}${i==S?(A?" \\u25b2":" \\u25bc"):""}`).join("");
$("h").onclick=e=>{const i=e.target.dataset.i;if(i==null)return;A=(i==S)?!A:(C[i][2]=="s");S=+i;$("h").innerHTML="";draw()};
$("q").oninput=draw;
async function go(){if(document.hidden)return;try{D=await(await fetch("api",{cache:"no-store"})).json();draw()}catch(e){}}
go();setInterval(go,2000);
</script>""".encode()


class H(BaseHTTPRequestHandler):
    def _authed(self):
        if not AUTH[0]:
            return True
        h = self.headers.get("Authorization", "")
        if h.startswith("Basic "):
            try:
                u, _, p = base64.b64decode(h[6:]).decode().partition(":")
                return hmac.compare_digest(u, AUTH[0]) & hmac.compare_digest(p, AUTH[1] or "")
            except Exception:
                pass
        return False

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, b"ok", "text/plain")
        if not self._authed():
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="procmon"')
            self.send_header("Content-Length", "0")
            return self.end_headers()
        if self.path.split("?")[0] == "/api":
            return self._send(200, snapshot(), "application/json")
        self._send(200, PAGE, "text/html; charset=utf-8")

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    if HOST != "127.0.0.1" and not AUTH[0]:
        print("WARNING: public bind without MONITOR_USER/MONITOR_PASS", flush=True)
    ThreadingHTTPServer((HOST, PORT), H).serve_forever()
