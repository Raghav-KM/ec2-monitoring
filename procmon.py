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
        if now - _cache["t"] < 0.2:           # many tabs -> one /proc scan
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
            "ts": now, "host": os.uname().nodename, "cores": os.cpu_count(), "cpu": round(cpu_pct, 1),
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
:root{color-scheme:light dark;--bg:#f4f5f7;--card:#fff;--text:#1b1f27;--mut:#6b7380;--line:#e4e7ec;--acc:#3b82f6;--ok:#16a34a;--warn:#d97706;--bad:#dc2626;--track:#e8ebf0;--hov:#f1f5fd;--star:#e0a100}
@media(prefers-color-scheme:dark){:root{--bg:#0e1116;--card:#161b22;--text:#e6e9ee;--mut:#8b95a3;--line:#262c36;--acc:#5b9bff;--ok:#3ccf86;--warn:#f0b429;--bad:#f06a6a;--track:#262c36;--hov:#1b2330;--star:#f5c542}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:12px 20px;background:var(--card);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}
h1{font-size:15px;margin:0;font-weight:650;letter-spacing:.01em}h1 span{color:var(--mut);font-weight:500;margin-left:8px}
.ctl{display:flex;gap:12px;align-items:center;color:var(--mut);font-size:12px;flex-wrap:wrap}
.dot{width:8px;height:8px;border-radius:50%;background:var(--ok);display:inline-block;margin-right:6px}.dot.off{background:var(--bad)}
select,input{font:inherit;color:var(--text);background:var(--card);border:1px solid var(--line);border-radius:8px;padding:5px 9px}
select{padding:4px 6px;font-size:12px}
main{max-width:1320px;margin:0 auto;padding:16px 20px 48px}
#cards{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(240px,1fr))}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
h3{margin:0 0 6px;font-size:11px;font-weight:600;color:var(--mut);text-transform:uppercase;letter-spacing:.06em}
.big{font-size:28px;font-weight:650;line-height:1.1;font-variant-numeric:tabular-nums}
.sub{color:var(--mut);font-size:12px;margin-top:3px;font-variant-numeric:tabular-nums}
.spark{display:block;width:100%;height:34px;margin-top:8px;color:var(--acc)}
.bar,.mb{height:5px;background:var(--track);border-radius:3px;overflow:hidden}.bar{margin-top:9px}
.bar i,.mb i{display:block;height:100%;background:var(--acc);border-radius:3px;transition:width .4s}
i.w{background:var(--warn)}i.x{background:var(--bad)}
.dk{margin-top:11px}.dk:first-child{margin-top:0}.dk .r{display:flex;justify-content:space-between;gap:8px;font-size:12px}
.dk .r span:first-child{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.dk .r span:last-child{color:var(--mut)}.dk .bar{margin-top:5px}
.sec{display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin:22px 0 8px;flex-wrap:wrap}
.sec h2{margin:0;font-size:13px;font-weight:650}.sec h2 small{color:var(--mut);font-weight:500;margin-left:6px}
.sec .tools{display:flex;gap:8px;align-items:center}
input[type=search]{width:260px;max-width:60vw}
.tw{background:var(--card);border:1px solid var(--line);border-radius:12px;overflow-x:auto}
table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}
th,td{padding:7px 12px;text-align:right;white-space:nowrap;border-bottom:1px solid var(--line);vertical-align:middle}
tbody tr:last-child td{border-bottom:0}
th:nth-child(-n+3),td:nth-child(-n+3){text-align:left}
th:first-child,td:first-child{width:34px;padding-right:0}
th{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut);font-weight:600;cursor:pointer;user-select:none}
th.s{color:var(--text)}
tbody tr:hover{background:var(--hov)}
tr.dim td{color:var(--mut)}tr.dim td.nm b{font-weight:500}
td.nm{max-width:360px}td.nm b{font-weight:600}
td.nm small{display:block;color:var(--mut);font-size:11px;overflow:hidden;text-overflow:ellipsis}
td.nm{overflow:hidden;text-overflow:ellipsis}
.tag{font-size:10px;padding:1px 6px;border-radius:9px;background:var(--track);color:var(--mut);margin-left:6px;vertical-align:1px}
.tag.bad{background:color-mix(in srgb,var(--bad) 18%,transparent);color:var(--bad)}
td.v{min-width:92px}td.v .mb{margin-top:3px}td.v em{font-style:normal;color:var(--mut);font-size:11px;margin-left:5px}
.pin{border:0;background:none;color:var(--mut);font-size:16px;line-height:1;cursor:pointer;padding:2px 4px;border-radius:5px;opacity:.55}
tr:hover .pin,.pin.on{opacity:1}.pin.on{color:var(--star)}.pin:hover{color:var(--star);background:var(--track)}
.empty{padding:18px;text-align:center;color:var(--mut);font-size:13px}
.note{color:var(--mut);font-size:12px;margin-top:12px}
</style>
<header>
 <h1>procmon<span id=host></span></h1>
 <div class=ctl><span><i id=dot class=dot></i><span id=live>connecting...</span></span>
  <label>refresh <select id=rf title="Faster sampling makes CPU % choppier: Linux counts CPU time in 10 ms steps"><option value=250>0.25 s</option><option value=500>0.5 s</option><option value=1000>1 s</option><option value=2000>2 s</option><option value=5000>5 s</option><option value=10000>10 s</option><option value=0>paused</option></select></label></div>
</header>
<main>
 <section id=cards>
  <div class=card><h3>CPU</h3><div class=big id=cpuV>-</div><div class=sub id=cpuS></div><svg id=cpuG class=spark viewBox="0 0 120 34" preserveAspectRatio=none></svg></div>
  <div class=card><h3>Memory</h3><div class=big id=memV>-</div><div class=sub id=memS></div><svg id=memG class=spark viewBox="0 0 120 34" preserveAspectRatio=none></svg></div>
  <div class=card><h3>Storage</h3><div id=disks></div></div>
  <div class=card><h3>System</h3><div class=big id=pc>-</div><div class=sub>processes</div><div class=sub id=ld style="margin-top:10px"></div><div class=sub id=up></div></div>
 </section>

 <div class=sec><h2>Pinned<small id=pn></small></h2></div>
 <div class=tw><table><thead id=ph></thead><tbody id=pb></tbody></table></div>

 <div class=sec><h2>All processes<small id=cnt></small></h2>
  <div class=tools><input id=q type=search placeholder="Filter processes   ( / )">
   <select id=lim><option value=25>top 25</option><option value=50>top 50</option><option value=100>top 100</option><option value=0>all</option></select></div></div>
 <div class=tw><table><thead id=h></thead><tbody id=b></tbody></table></div>
 <p class=note>CPU is a percentage of one core (200% = two cores busy). Pins are saved in this browser and follow the command line, so they survive restarts and show "not running" when the process is gone. Disk read/write is real storage I/O; "-" means the process is not readable.</p>
</main>
<script>
const $=i=>document.getElementById(i);
const E=s=>String(s).replace(/[&<>"]/g,c=>"&#"+c.charCodeAt(0)+";");
const B=n=>{if(n==null)return"-";let u="BKMGT",i=0;while(n>=1024&&i<4){n/=1024;i++}return(i?n.toFixed(n<10?2:1):Math.round(n))+" "+u[i]+(i?"B":"")};
const R=n=>n==null?"-":n<1?"0":B(n)+"/s";
const lv=(p,w,x)=>p>=x?"x":p>=w?"w":"";
const store={get(k,d){try{const v=localStorage.getItem(k);return v==null?d:JSON.parse(v)}catch(e){return d}},set(k,v){try{localStorage.setItem(k,JSON.stringify(v))}catch(e){}}};

let D=null,timer=null,busy=false,pins=store.get("procmon.pins",[]),sortCol=store.get("procmon.sort",3),asc=store.get("procmon.asc",false);
const hist={cpu:[],mem:[]},H=60;
$("rf").value=store.get("procmon.rf",2000);$("lim").value=store.get("procmon.lim",50);

// columns: label, sort index into the process array (null = not sortable)
const COLS=[["",null],["Process",1],["User",2],["PID",0],["CPU",3],["RAM",4],["Disk read/s",5],["Disk write/s",6],["Threads",7]];
function head(el,sortable){el.innerHTML="<tr>"+COLS.map((c,i)=>`<th data-i="${i}"${sortable&&c[1]===sortCol?' class=s':''}>${c[0]}${sortable&&c[1]===sortCol?(asc?" ▲":" ▼"):""}</th>`).join("")+"</tr>"}
function spark(el,a,cls){
 if(a.length<2){el.innerHTML="";return}
 const s=120/(H-1),x0=(H-a.length)*s,pts=a.map((v,i)=>(x0+i*s).toFixed(1)+","+(32-Math.min(v,100)/100*30).toFixed(1)).join(" ");
 el.innerHTML=`<polygon points="${x0.toFixed(1)},34 ${pts} 120,34" fill="currentColor" opacity=".12"/><polyline points="${pts}" fill="none" stroke="currentColor" stroke-width="1.5" vector-effect="non-scaling-stroke"/>`;
}
const isPinned=k=>pins.some(p=>p.k===k);
function toggle(k,n){pins=isPinned(k)?pins.filter(p=>p.k!==k):pins.concat([{k:k,n:n}]);store.set("procmon.pins",pins);draw()}

function cards(){
 const m=D.mem[0]/D.mem[1]*100;
 $("host").textContent=D.host;document.title=D.host+" - procmon";
 $("cpuV").textContent=D.cpu.toFixed(1)+"%";$("cpuS").textContent=D.cores+" cores · load "+D.load.map(x=>x.toFixed(2)).join("  ");
 $("memV").textContent=m.toFixed(1)+"%";$("memS").textContent=B(D.mem[0])+" of "+B(D.mem[1])+(D.swap[1]?" · swap "+B(D.swap[0]):"");
 spark($("cpuG"),hist.cpu);spark($("memG"),hist.mem);
 $("disks").innerHTML=D.disks.map(d=>{const p=d[1]/d[2]*100;return`<div class=dk><div class=r><span title="${E(d[0])}">${E(d[0])}</span><span>${B(d[1])} / ${B(d[2])} · ${p.toFixed(0)}%</span></div><div class=bar><i class="${lv(p,70,90)}" style="width:${p}%"></i></div></div>`}).join("")||'<div class=sub>no disks</div>';
 $("pc").textContent=D.procs.length;
 $("ld").textContent="load average "+D.load.map(x=>x.toFixed(2)).join(" · ");
 const u=D.up;$("up").textContent="up "+(u>=86400?Math.floor(u/86400)+"d ":"")+Math.floor(u%86400/3600)+"h "+Math.floor(u%3600/60)+"m";
}
function bar(v,w,x,txt,extra){const c=lv(v,w,x);return`<td class=v>${txt}${extra||""}<div class=mb><i class="${c}" style="width:${Math.max(0,Math.min(v,100))}%"></i></div>`}
// o: key, name, sub, pid, user, cpu, rss, rd, wr, thr, star, tag, dim
function row(o){
 const mt=D.mem[1];
 const none=o.cpu==null;
 return`<tr${o.dim?' class=dim':''}><td><button class="pin${o.star?' on':''}" data-k="${E(o.k)}" data-n="${E(o.n)}" title="${o.star?'Unpin':'Pin'}">${o.star?'★':'☆'}</button>`
 +`<td class=nm title="${E(o.k)}"><b>${E(o.n)}</b>${o.tag?` <span class="tag${o.tagBad?' bad':''}">${o.tag}</span>`:''}${o.sub?`<small>${E(o.sub)}</small>`:''}`
 +`<td>${E(o.user)}<td>${o.pid}`
 +(none?'<td class=v>-<td class=v>-<td>-<td>-<td>-'
  :bar(o.cpu,40,80,o.cpu.toFixed(1)+"%")
  +bar(o.rss/mt*100*4,40,100,B(o.rss),`<em>${(o.rss/mt*100).toFixed(1)}%</em>`)
  +`<td>${R(o.rd)}<td>${R(o.wr)}<td>${o.thr}`)+"</tr>";
}
const sumN=(a,i)=>{let s=null;for(const p of a)if(p[i]!=null)s=(s||0)+p[i];return s};
function pinned(){
 $("pn").textContent=pins.length?pins.length+" pinned":"";
 if(!pins.length){$("pb").innerHTML='<tr><td colspan=9 class=empty>Nothing pinned yet. Click ☆ next to a process to keep it here.</td></tr>';return}
 const g=new Map();for(const p of D.procs){const a=g.get(p[8]);a?a.push(p):g.set(p[8],[p])}
 $("pb").innerHTML=pins.map(pn=>{
  const a=g.get(pn.k);
  if(!a)return row({k:pn.k,n:pn.n,sub:pn.k!==pn.n?pn.k:"",pid:"-",user:"-",cpu:null,star:true,dim:true,tag:"not running",tagBad:true});
  const p0=a[0];
  return row({k:pn.k,n:p0[1],sub:p0[8]!==p0[1]?p0[8]:"",pid:a.length>1?"×"+a.length:p0[0],user:p0[2],cpu:a.reduce((s,p)=>s+p[3],0),rss:a.reduce((s,p)=>s+p[4],0),rd:sumN(a,5),wr:sumN(a,6),thr:a.reduce((s,p)=>s+p[7],0),star:true,tag:a.length>1?a.length+" processes":""});
 }).join("");
}
function table(){
 const q=$("q").value.trim().toLowerCase();
 const pk=new Set(pins.map(p=>p.k));let r=D.procs.filter(p=>!pk.has(p[8]));if(q)r=r.filter(p=>(p[1]+" "+p[2]+" "+p[0]+" "+p[8]).toLowerCase().includes(q));
 const t=sortCol===1||sortCol===2,d=asc?1:-1;
 r=r.slice().sort((a,b)=>{const x=a[sortCol],y=b[sortCol];if(x==null&&y==null)return 0;if(x==null)return 1;if(y==null)return-1;return(t?String(x).localeCompare(y):x-y)*d});
 const total=r.length,lim=+$("lim").value;if(lim)r=r.slice(0,lim);
 $("cnt").textContent=r.length+" of "+total;
 $("b").innerHTML=r.map(p=>row({k:p[8],n:p[1],sub:p[8]!==p[1]?p[8]:"",pid:p[0],user:p[2],cpu:p[3],rss:p[4],rd:p[5],wr:p[6],thr:p[7],star:false})).join("")||'<tr><td colspan=9 class=empty>No matching processes</td></tr>';
}
function draw(){if(!D)return;cards();pinned();table()}

function sortBy(e){const th=e.target.closest("th");if(!th)return;const c=COLS[+th.dataset.i][1];if(c==null)return;
 if(c===sortCol)asc=!asc;else{sortCol=c;asc=(c===1||c===2)}
 store.set("procmon.sort",sortCol);store.set("procmon.asc",asc);head($("h"),true);table()}
$("h").onclick=sortBy;
document.addEventListener("click",e=>{const b=e.target.closest(".pin");if(b)toggle(b.dataset.k,b.dataset.n)});
document.addEventListener("keydown",e=>{if(e.key==="/"&&document.activeElement!==$("q")){e.preventDefault();$("q").focus()}});
$("q").oninput=table;
$("lim").onchange=()=>{store.set("procmon.lim",+$("lim").value);table()};
$("rf").onchange=()=>{store.set("procmon.rf",+$("rf").value);schedule()};
function status(ok,t){$("dot").className="dot"+(ok?"":" off");$("live").textContent=ok?"live · "+t:"disconnected"}
async function go(){
 if(document.hidden||busy)return;
 busy=true;
 try{
  const r=await fetch("api",{cache:"no-store"});
  if(r.status===401){location.reload();return}
  D=await r.json();
  hist.cpu.push(D.cpu);hist.mem.push(D.mem[0]/D.mem[1]*100);
  if(hist.cpu.length>H){hist.cpu.shift();hist.mem.shift()}
  status(true,new Date(D.ts*1000).toLocaleTimeString());draw();
 }catch(e){status(false)}
 busy=false;
}
function schedule(){clearInterval(timer);const ms=+$("rf").value;if(ms)timer=setInterval(go,ms)}
document.addEventListener("visibilitychange",()=>{if(!document.hidden)go()});
head($("ph"),false);head($("h"),true);go();schedule();
</script>
""".encode()


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
