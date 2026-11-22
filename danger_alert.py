#!/usr/bin/env python3
"""
Danger Alert - silent, instant alerts to a chosen group of friends on the office LAN.

  danger-alert                 open the settings window (same as `setup`)
  danger-alert setup           settings window: devices, messages, hotkeys
  danger-alert install         start in background at login + register hotkeys
  danger-alert uninstall       remove autostart + hotkeys, stop background service
  danger-alert run             the background listener (autostart runs this)
  danger-alert send ID         send a configured message, e.g. `send danger`
  danger-alert send --text T   send any custom text
  danger-alert scan            list Danger Alert devices with your group code
  danger-alert add-device NAME HOST ID
  danger-alert devices         list your configured devices
  danger-alert status          show status and config location
  danger-alert doctor          explain why alerts or scan aren't working

Only devices in YOUR device list receive your alerts, and you only accept alerts
from devices in your list that also know the group code.
"""
import argparse, ast, hashlib, hmac, json, logging, os, platform, re, secrets, shlex
import shutil, socket, subprocess, sys, threading, time
from pathlib import Path

APP = "danger-alert"
VERSION = "2.1.1"
IS_WIN = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"
IS_LINUX = not (IS_WIN or IS_MAC)
FROZEN = getattr(sys, "frozen", False)
MAX_AGE = 300      # seconds; tolerates some clock skew between machines
COOLDOWN = 1.2     # seconds between sends (stops key-repeat spam)

if IS_WIN:
    _base = Path(os.environ.get("APPDATA", Path.home()))
    CONFIG_DIR = STATE_DIR = _base / "DangerAlert"
else:
    CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / APP
    STATE_DIR = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state") / APP
CONFIG_FILE = CONFIG_DIR / "config.json"
SEEN_FILE = STATE_DIR / "seen-ips.json"
PID_FILE = STATE_DIR / "daemon.pid"
LAST_SEND_FILE = STATE_DIR / "last-send"
LOG_FILE = STATE_DIR / "danger-alert.log"
DISCOVERED_FILE = STATE_DIR / "discovered.json"

DEFAULT_MESSAGES = [
    {"id": "danger", "text": "⚠️ DANGER - heads up!", "hotkey": "<Control><Alt>d", "urgent": True},
    {"id": "clear", "text": "✅ All clear", "hotkey": "<Control><Alt>c", "urgent": False},
    {"id": "coffee", "text": "☕ Coffee break?", "hotkey": "<Control><Alt>k", "urgent": False},
]

log = logging.getLogger(APP)


# ======================================================================== config
def new_config():
    return {
        "device_id": secrets.token_hex(4),
        "name": (os.environ.get("USER") or os.environ.get("USERNAME") or socket.gethostname()).title(),
        "group_code": "",
        "port": 50505,
        "devices": [],                 # [{"id","name","host","ip"}]
        "messages": [dict(m) for m in DEFAULT_MESSAGES],
        "sound": True,
        "confirm_sent": False,         # tiny "sent to 3/3" note on YOUR screen
        "only_my_devices": True,       # ignore alerts from devices not in your list
    }


def load_config():
    cfg = new_config()
    if CONFIG_FILE.exists():
        try:
            cfg.update(json.loads(CONFIG_FILE.read_text(encoding="utf-8")))
        except Exception as e:
            log.error("config unreadable (%s), using defaults", e)
    return cfg


def save_config(cfg):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
    if not IS_WIN:
        os.chmod(tmp, 0o600)           # group code lives here
    os.replace(tmp, CONFIG_FILE)


def safe_id(s):
    return re.sub(r"[^a-z0-9-]", "-", s.strip().lower()).strip("-")[:32] or "msg"


def read_json(path, default):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return default


# ====================================================================== protocol
def norm_code(code):
    """Group codes are compared ignoring case and spaces ('Ab 12' == 'ab12')."""
    return re.sub(r"\s+", "", code or "").lower()


def code_check(code):
    """4-char fingerprint people can compare out loud to confirm they typed the same code."""
    return hashlib.sha256(("danger-alert:" + norm_code(code)).encode()).hexdigest()[:4].upper()


def _mac(code, text):
    return hmac.new(norm_code(code).encode(), text.encode(), hashlib.sha256).hexdigest()


def pack(body, code):
    b = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    sig = _mac(code, b)
    return json.dumps({"v": 2, "b": b, "s": sig}).encode()


def unpack(data, code):
    try:
        pkt = json.loads(data)
        if not hmac.compare_digest(_mac(code, pkt["b"]), pkt["s"]):
            return None
        return json.loads(pkt["b"])
    except Exception:
        return None


def is_ip(s):
    try:
        socket.inet_aton(s)
        return s.count(".") == 3
    except OSError:
        return False


def local_hostname():
    h = socket.gethostname()
    return h if "." in h or IS_WIN else h + ".local"   # Ubuntu resolves .local via mDNS


def local_networks():
    """[{name, ip, mask, bcast, default, kind}] for each IPv4 interface that is up."""
    nets = []
    default_ifaces = set()
    try:
        for line in Path("/proc/net/route").read_text().splitlines()[1:]:
            f = line.split()
            if len(f) > 2 and f[1] == "00000000":
                default_ifaces.add(f[0])
    except OSError:
        pass
    if IS_LINUX:
        import fcntl, struct
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for _, name in socket.if_nameindex():
            if name == "lo":
                continue
            ifr = struct.pack("256s", name.encode()[:15])
            try:
                ip = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, ifr)[20:24])     # SIOCGIFADDR
                mask = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x891B, ifr)[20:24])   # SIOCGIFNETMASK
            except OSError:
                continue
            ipn = int.from_bytes(socket.inet_aton(ip), "big")
            mn = int.from_bytes(socket.inet_aton(mask), "big")
            bcast = socket.inet_ntoa(((ipn & mn) | (~mn & 0xFFFFFFFF)).to_bytes(4, "big"))
            kind = ("vpn" if re.match(r"(tun|tap|wg|ppp|vpn|tailscale|zt)", name) else
                    "virtual" if re.match(r"(docker|br-|veth|virbr|lxc|vmnet|vboxnet)", name) else
                    "wifi" if re.match(r"(wl)", name) else "wired")
            nets.append({"name": name, "ip": ip, "mask": mask, "bcast": bcast,
                         "default": name in default_ifaces, "kind": kind})
        s.close()
    if not nets:   # Windows / macOS fallback: primary IP, assume a /24
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("10.255.255.255", 1))          # no packet is sent
            ip = s.getsockname()[0]
            s.close()
            nets.append({"name": "primary", "ip": ip, "mask": "255.255.255.0",
                         "bcast": ip.rsplit(".", 1)[0] + ".255", "default": True, "kind": "?"})
        except OSError:
            pass
    return nets


def lan_ip(nets=None):
    """The address friends should use to reach this PC (real network, not Docker/VPN)."""
    nets = nets if nets is not None else local_networks()
    real = [n for n in nets if n["kind"] in ("wired", "wifi", "?")]
    for n in sorted(real, key=lambda n: not n["default"]):
        return n["ip"]
    return nets[0]["ip"] if nets else "?"


def same_subnet(ip, nets):
    try:
        n = int.from_bytes(socket.inet_aton(ip), "big")
    except OSError:
        return False
    if ip.startswith("127."):
        return True
    for x in nets:
        m = int.from_bytes(socket.inet_aton(x["mask"]), "big")
        if n & m == int.from_bytes(socket.inet_aton(x["ip"]), "big") & m:
            return True
    return False


def resolve(host, deadline=1.5):
    if is_ip(host):
        return [host]
    out = []
    def look():
        try:
            out.extend(ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET))
        except OSError:
            pass
    t = threading.Thread(target=look, daemon=True)
    t.start()
    t.join(deadline)
    return list(dict.fromkeys(out))


def device_targets(dev, seen, deadline=0.8):
    """Every IP this device might be at: last seen, host lookup, stored IP."""
    ips = [x for x in (seen.get(dev.get("id")), dev.get("ip")) if x]
    host = (dev.get("host") or "").strip()
    if host and is_ip(host):
        ips.insert(0, host)
    elif host:
        out = []
        def look():
            try:
                out.extend(ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET))
            except OSError:
                pass
        t = threading.Thread(target=look, daemon=True)
        t.start()
        t.join(deadline)
        ips = out + ips
    return list(dict.fromkeys(ips))


def send_alert(cfg, msg_id=None, text=None, only=None, quiet=False):
    """Send to configured devices. Returns {device_id: 'ok'|'rejected'|'no reply'}."""
    if not cfg.get("group_code"):
        raise SystemExit("No group code set. Run `danger-alert setup` first.")
    if msg_id:
        m = next((m for m in cfg["messages"] if m["id"] == msg_id), None)
        if not m:
            raise SystemExit(f"Unknown message id '{msg_id}'. Known: "
                             + ", ".join(m["id"] for m in cfg["messages"]))
        text, urgent = m["text"], bool(m.get("urgent"))
    else:
        urgent = False
    devices = [d for d in cfg["devices"] if not only or d["id"] in only]
    if not devices:
        log.warning("no devices configured; nothing sent")
        return {}

    nonce = secrets.token_hex(8)
    body = {"type": "alert", "from_id": cfg["device_id"], "from_name": cfg["name"],
            "msg_id": msg_id or "custom", "text": text, "urgent": urgent,
            "nonce": nonce, "ts": time.time()}
    pkt = pack(body, cfg["group_code"])
    seen = read_json(SEEN_FILE, {})

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.05)
    results = {d["id"]: "no reply" for d in devices}
    targets = {}
    threads = []
    for d in devices:                       # resolve hosts in parallel
        def work(d=d):
            targets[d["id"]] = device_targets(d, seen)
        t = threading.Thread(target=work, daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(1.0)

    end = time.time() + 0.9
    rounds = 0
    while time.time() < end and "no reply" in results.values():
        if rounds < 4:                      # UDP may drop: resend a few times
            for did, ips in list(targets.items()):
                if results.get(did) == "no reply":
                    for ip in ips:
                        try:
                            sock.sendto(pkt, (ip, cfg["port"]))
                        except OSError:
                            pass
            rounds += 1
        try:
            data, _ = sock.recvfrom(4096)
        except (socket.timeout, OSError):
            continue
        ack = unpack(data, cfg["group_code"])
        if ack and ack.get("type") == "ack" and ack.get("nonce") == nonce and ack.get("from_id") in results:
            results[ack["from_id"]] = "ok" if ack.get("accepted") else "rejected"
    sock.close()

    names = {d["id"]: d["name"] for d in devices}
    log.info("sent '%s' -> %s", text, ", ".join(f"{names[k]}:{v}" for k, v in results.items()))
    if cfg.get("confirm_sent") and not quiet:
        ok = sum(v == "ok" for v in results.values())
        notify("Danger Alert", f"Sent to {ok}/{len(results)}", urgent=False, sound=False, transient=True)
    return results


def scan(cfg, wait=2.5):
    """Find other running Danger Alert devices that use the same group code."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(0.2)
    nonce = secrets.token_hex(8)
    pkt = pack({"type": "hello", "from_id": cfg["device_id"], "from_name": cfg["name"],
                "nonce": nonce, "ts": time.time()}, cfg["group_code"])
    found = {}
    start = time.time()
    end = start + wait
    sent = 0
    dests = ["255.255.255.255"] + [n["bcast"] for n in local_networks() if n["kind"] != "virtual"]
    while time.time() < end:
        if sent < 3:
            for dst in dests:
                try:
                    sock.sendto(pkt, (dst, cfg["port"]))
                except OSError:
                    pass
            sent += 1
        try:
            data, addr = sock.recvfrom(4096)
        except (socket.timeout, OSError):
            continue
        r = unpack(data, cfg["group_code"])
        if r and r.get("type") == "here" and r.get("nonce") == nonce and r["from_id"] != cfg["device_id"]:
            found[r["from_id"]] = {"id": r["from_id"], "name": r.get("from_name", "?"),
                                   "host": r.get("hostname") or addr[0], "ip": addr[0]}
    sock.close()
    # replies that came in on the main port (get through a firewall that allows it)
    for did, r in read_json(DISCOVERED_FILE, {}).items():
        if r.get("nonce") == nonce and did != cfg["device_id"] and did not in found:
            found[did] = {k: r[k] for k in ("id", "name", "host", "ip")}
    return list(found.values())


# ================================================================ diagnostics
def probe(cfg, ip, timeout=1.5):
    """Ask whatever listens at ip:port who it is. Works even if group codes differ."""
    nonce = secrets.token_hex(8)
    pkt = json.dumps({"v": 2, "probe": nonce, "from_id": cfg["device_id"],
                      "proof": _mac(cfg["group_code"], "probe:" + nonce)}).encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.3)
    try:
        s.connect((ip, cfg["port"]))
    except OSError as e:
        return {"status": "unreachable", "detail": str(e)}
    end = time.time() + timeout
    while time.time() < end:
        try:
            s.send(pkt)
            r = json.loads(s.recv(4096))
            if r.get("pong") != nonce:
                continue
            if not r.get("code_ok"):
                return {"status": "code_mismatch", "version": r.get("ver")}
            if not hmac.compare_digest(_mac(cfg["group_code"], "pong:" + nonce + ":" + r.get("id", "")),
                                       r.get("proof", "")):
                continue
            return {"status": "ok", "id": r.get("id"), "name": r.get("name"),
                    "knows_you": r.get("knows_you"), "version": r.get("ver")}
        except ConnectionRefusedError:
            return {"status": "not_listening"}     # PC answered: nothing on that port
        except (socket.timeout, ValueError):
            continue
        except OSError as e:
            return {"status": "unreachable", "detail": str(e)}
    return {"status": "no_response"}


def icmp_ping(ip):
    if not shutil.which("ping"):
        return None
    flag = ["-n", "1", "-w", "1000"] if IS_WIN else ["-c", "1", "-W", "1"]
    try:
        return subprocess.run(["ping", *flag, ip], env=clean_env(), capture_output=True,
                              timeout=3).returncode == 0
    except Exception:
        return None


def ufw_enabled():
    try:
        return bool(re.search(r"^ENABLED=yes", Path("/etc/ufw/ufw.conf").read_text(), re.M))
    except OSError:
        return False


def explain_device(cfg, dev, seen=None):
    """(ok: bool, one-line explanation) for one configured device."""
    host = (dev.get("host") or dev.get("ip") or "").strip()
    ips = list(dict.fromkeys(resolve(host) + [x for x in ((seen or {}).get(dev["id"]), dev.get("ip")) if x]))
    if not ips:
        return False, f"can't find '{host}' on the network. Use their LAN address instead (shown on their 'This device' tab)"
    port = cfg["port"]
    reasons = []
    nets = local_networks()
    for ip in ips:
        own = next((n for n in nets if n["ip"] == ip), None)
        virt = next((n for n in nets if n["kind"] in ("virtual", "vpn") and same_subnet(ip, [n])), None)
        if own or virt:
            n = own or virt
            what = "THIS PC's own" if own else "a"
            reasons.append(f"{ip} is {what} {'Docker/virtual' if n['kind'] == 'virtual' else n['kind'].upper()} "
                           f"network address ({n['name']}), not their PC. Use their LAN address instead: "
                           "it's shown on the 'This device' tab of their Danger Alert")
            continue
        r = probe(cfg, ip)
        st = r["status"]
        if st == "ok":
            if r["id"] != dev["id"]:
                return False, (f"{ip} is {r['name']} with device ID {r['id']}, but you entered {dev['id']}. "
                               "Fix the ID (remove + add again)")
            if not r.get("knows_you"):
                return False, f"reachable at {ip}, but they haven't added you (your ID: {cfg['device_id']})"
            return True, f"OK at {ip}"
        if st == "code_mismatch":
            return False, (f"Danger Alert is running at {ip}, but with a DIFFERENT group code. "
                           f"Compare the 'code check' on both PCs (yours: {code_check(cfg['group_code'])})")
        if st == "not_listening":
            reasons.append(f"{ip}: the PC is there, but Danger Alert isn't running on it "
                           "(on their PC: open Danger Alert Settings and click Save & apply)")
            continue
        pinged = icmp_ping(ip)
        nets = local_networks()
        if not same_subnet(ip, nets):
            reasons.append(f"{ip}: not on your network ({', '.join(n['ip'] + '/' + n['mask'] for n in nets)}). "
                           "Wrong IP, or they're on another Wi-Fi/VPN")
        elif pinged:
            reasons.append(f"{ip}: PC replies to ping, but UDP {port} gets no answer. Their firewall is blocking it "
                           f"(on their PC: sudo ufw allow {port}/udp) or the app is an old version")
        elif pinged is False:
            reasons.append(f"{ip}: no answer at all. PC is off/asleep, the IP changed, or the office Wi-Fi blocks "
                           "PC-to-PC traffic (client isolation)")
        else:
            reasons.append(f"{ip}: no answer (firewall, app not running, or Wi-Fi client isolation)")
    return False, " | ".join(reasons)


def recent_log(pattern, hours=2):
    out = []
    cut = time.time() - hours * 3600
    try:
        for line in LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()[-3000:]:
            if re.search(pattern, line):
                try:
                    t = time.mktime(time.strptime(line[:19], "%Y-%m-%d %H:%M:%S"))
                except ValueError:
                    continue
                if t >= cut:
                    out.append(line)
    except OSError:
        pass
    return out


def doctor(cfg):
    L = []
    add = L.append
    add(f"Danger Alert {VERSION} - diagnosis ({time.strftime('%Y-%m-%d %H:%M')})")
    add(f"This PC:  {cfg['name']}   device ID {cfg['device_id']}   port {cfg['port']}/udp")
    add(f"Group code check: {code_check(cfg['group_code'])}   <- must be the SAME on every PC")
    add(f"LAN address: {lan_ip()}   <- friends use this to add you manually")
    add("")
    me = probe(dict(cfg), "127.0.0.1", timeout=1.0)
    if me["status"] == "ok":
        add("✔ Background service is running")
    elif me["status"] == "no_response" and port_in_use(cfg["port"]):
        add(f"✘ Port {cfg['port']} is held by an OLD copy or another program. Run: pkill -f 'danger-alert run' ; "
            "pkill -f alert.py   then click Save & apply")
    else:
        add("✘ Background service is NOT running. Click Save & apply (or run: danger-alert install)")
    if IS_LINUX:
        if ufw_enabled():
            add(f"! Firewall (ufw) is ON. Make sure it allows the app: sudo ufw allow {cfg['port']}/udp"
                + ("   (already allowed via this app)" if cfg.get("ufw_allowed") else ""))
        else:
            add("✔ Firewall (ufw) is off")
    nets = local_networks()
    add("")
    add("Network:")
    for n in nets:
        add(f"   {n['name']:<12} {n['ip']:<16} mask {n['mask']:<16} {n['kind']}"
            + ("  [default route]" if n["default"] else ""))
    if any(n["kind"] == "vpn" and n["default"] for n in nets):
        add("! A VPN carries your default route. Office LAN traffic may go into the VPN instead. "
            "Try with the VPN off, or add devices by IP")
    bad = recent_log(r"different group code")
    if bad:
        ips = sorted({re.search(r"from (\S+)", b).group(1) for b in bad if re.search(r"from (\S+)", b)})
        add(f"! Recently got packets with a different group code from: {', '.join(ips)}")
    add("")
    devs = cfg["devices"]
    add(f"Devices in your list ({len(devs)}):" if devs else "No devices in your list yet.")
    seen = read_json(SEEN_FILE, {})
    results = {}
    def check(d):
        try:
            results[d["id"]] = explain_device(cfg, d, seen)
        except Exception as e:
            results[d["id"]] = (False, f"check failed: {e}")
    scan_result = []
    threads = [threading.Thread(target=check, args=(d,), daemon=True) for d in devs]
    threads.append(threading.Thread(target=lambda: scan_result.extend(scan(cfg, wait=2.0)), daemon=True))
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)
    for d in devs:
        ok, why = results.get(d["id"], (False, "check timed out"))
        add(f"   {'✔' if ok else '✘'} {d['name']} ({d.get('host') or d.get('ip')}): {why}")
    add("")
    found = scan_result
    add(f"Scan found {len(found)} device(s) with your group code"
        + (": " + ", ".join(f"{f['name']} {f['ip']}" for f in found) if found else ""))
    if not found:
        add("   (if adding by IP works but scan doesn't, the Wi-Fi blocks broadcasts; that's fine)")
    return L


# ================================================================= notifications
def clean_env():
    """PyInstaller sets LD_LIBRARY_PATH to its bundle; system tools must not see it."""
    env = dict(os.environ)
    if FROZEN and IS_LINUX:
        orig = env.pop("LD_LIBRARY_PATH_ORIG", None)
        if orig is not None:
            env["LD_LIBRARY_PATH"] = orig
        else:
            env.pop("LD_LIBRARY_PATH", None)
    return env


def _run(cmd):
    try:
        subprocess.Popen(cmd, env=clean_env(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except OSError:
        return False


def play_sound(urgent):
    if IS_WIN:
        import winsound
        winsound.MessageBeep(0x30 if urgent else 0x40)
    elif IS_MAC:
        _run(["afplay", "/System/Library/Sounds/" + ("Sosumi.aiff" if urgent else "Pop.aiff")])
    else:
        name = "dialog-warning" if urgent else "message"
        f = f"/usr/share/sounds/freedesktop/stereo/{name}.oga"
        if not (Path(f).exists() and shutil.which("paplay") and _run(["paplay", f])):
            if shutil.which("canberra-gtk-play"):
                _run(["canberra-gtk-play", "-i", name])


def notify(title, text, urgent=True, sound=True, transient=False):
    log.info("NOTIFY %s | %s", title, text)
    try:
        if sound:
            play_sound(urgent)
        if IS_WIN:
            import ctypes
            flags = (0x30 if urgent else 0x40) | 0x40000 | 0x1000   # icon | TOPMOST | SYSTEMMODAL
            threading.Thread(target=ctypes.windll.user32.MessageBoxW,
                             args=(0, text, title, flags), daemon=True).start()
        elif IS_MAC:
            t = text.replace('"', "'")
            _run(["osascript", "-e", f'display notification "{t}" with title "{title}"'])
        elif shutil.which("notify-send"):
            cmd = ["notify-send", "-a", "Danger Alert", "-u", "critical" if urgent else "normal",
                   "-i", "dialog-warning" if urgent else "dialog-information"]
            if transient:
                cmd += ["-e", "-t", "1500"]
            _run(cmd + [title, text])
        else:   # gdbus ships with every GNOME desktop
            hints = "{'urgency': <byte 2>}" if urgent else "{}"
            _run(["gdbus", "call", "--session", "--dest", "org.freedesktop.Notifications",
                  "--object-path", "/org/freedesktop/Notifications",
                  "--method", "org.freedesktop.Notifications.Notify", "Danger Alert", "0",
                  "dialog-warning", title, text, "[]", hints, "-1"])
    except Exception as e:
        log.error("notification failed: %s", e)


# ======================================================================= hotkeys
GNOME_SCHEMA = "org.gnome.settings-daemon.plugins.media-keys"
GNOME_KB = GNOME_SCHEMA + ".custom-keybinding"
GNOME_BASE = "/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/"


def gnome_ok():
    if not (IS_LINUX and shutil.which("gsettings")):
        return False
    r = subprocess.run(["gsettings", "get", GNOME_SCHEMA, "custom-keybindings"],
                       env=clean_env(), capture_output=True, text=True)
    return r.returncode == 0


def _gs(*args):
    return subprocess.run(["gsettings", *args], env=clean_env(), capture_output=True, text=True)


def gnome_set_shortcuts(cfg, exe_cmd):
    """Register hotkeys as GNOME custom shortcuts (works on Wayland and X11)."""
    raw = _gs("get", GNOME_SCHEMA, "custom-keybindings").stdout.strip()
    raw = raw[len("@as "):] if raw.startswith("@as ") else raw
    current = ast.literal_eval(raw or "[]")
    keep = [p for p in current if "/danger-alert-" not in p]
    for p in current:
        if "/danger-alert-" in p:
            _gs("reset-recursively", f"{GNOME_KB}:{p}")
    new = []
    for m in cfg["messages"] if exe_cmd else []:
        if not m.get("hotkey"):
            continue
        path = f"{GNOME_BASE}danger-alert-{safe_id(m['id'])}/"
        _gs("set", f"{GNOME_KB}:{path}", "name", f"Danger Alert: {m['id']}")
        _gs("set", f"{GNOME_KB}:{path}", "command", f"{exe_cmd} send {shlex.quote(m['id'])}")
        _gs("set", f"{GNOME_KB}:{path}", "binding", m["hotkey"])
        new.append(path)
    _gs("set", GNOME_SCHEMA, "custom-keybindings", str(keep + new))
    return len(new)


def pretty_hotkey(hk):
    """'<Control><Alt>d' -> 'Ctrl+Alt+D'"""
    if not hk:
        return ""
    names = {"control": "Ctrl", "primary": "Ctrl", "alt": "Alt", "shift": "Shift", "super": "Super"}
    mods = [names.get(m.lower(), m) for m in re.findall(r"<(\w+)>", hk)]
    key = re.sub(r"<\w+>", "", hk)
    return "+".join(mods + [key.upper() if len(key) == 1 else key])


def to_pynput(hk):
    """'<Control><Alt>d' -> '<ctrl>+<alt>+d'"""
    mods = re.findall(r"<(\w+)>", hk)
    key = re.sub(r"<\w+>", "", hk).strip().lower()
    mp = {"control": "ctrl", "primary": "ctrl", "ctrl": "ctrl", "alt": "alt", "shift": "shift",
          "super": "cmd", "meta": "cmd"}
    parts = [f"<{mp.get(m.lower(), m.lower())}>" for m in mods]
    if key:
        parts.append(key if len(key) == 1 else f"<{key}>")
    return "+".join(parts)


class PynputHotkeys:
    """In-process hotkeys for Windows / macOS / non-GNOME X11."""
    def __init__(self):
        self.listener = None

    def start(self, cfg):
        self.stop()
        try:
            from pynput import keyboard
        except Exception as e:
            log.warning("in-process hotkeys unavailable (%s)", e)
            return
        last = [0.0]
        def fire(mid):
            if time.time() - last[0] < COOLDOWN:
                return
            last[0] = time.time()
            threading.Thread(target=send_alert, args=(load_config(), mid), daemon=True).start()
        mapping = {to_pynput(m["hotkey"]): (lambda mid=m["id"]: fire(mid))
                   for m in cfg["messages"] if m.get("hotkey")}
        try:
            self.listener = keyboard.GlobalHotKeys(mapping)
            self.listener.start()
            log.info("hotkeys active: %s", ", ".join(mapping))
        except Exception as e:
            log.error("could not start hotkeys: %s", e)

    def stop(self):
        if self.listener:
            self.listener.stop()
            self.listener = None


def hotkey_backend():
    return "gnome" if gnome_ok() else "pynput"


# ===================================================================== daemon
def port_in_use(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("", port))
        return False
    except OSError:
        return True
    finally:
        s.close()


def run_daemon():
    cfg = load_config()
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    def bind(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((os.environ.get("DANGER_ALERT_BIND", ""), port))  # no SO_REUSEADDR: a second instance fails here
        s.settimeout(2.0)
        return s

    try:
        sock = bind(cfg["port"])
    except OSError:
        log.info("already running (port %s busy)", cfg["port"])
        print("Danger Alert is already running.")
        return
    PID_FILE.write_text(str(os.getpid()))
    log.info("listening on UDP %s as %s [%s]", cfg["port"], cfg["name"], cfg["device_id"])

    hotkeys = PynputHotkeys() if hotkey_backend() == "pynput" else None
    if hotkeys:
        hotkeys.start(cfg)
    mtime = CONFIG_FILE.stat().st_mtime if CONFIG_FILE.exists() else 0
    seen_nonces, seen_ips, wrong_code_logged = {}, read_json(SEEN_FILE, {}), {}

    while True:
        # pick up changes made in the settings window, without restarting
        m = CONFIG_FILE.stat().st_mtime if CONFIG_FILE.exists() else 0
        if m != mtime:
            mtime, old_port = m, cfg["port"]
            cfg = load_config()
            log.info("config reloaded")
            if cfg["port"] != old_port:
                sock.close()
                sock = bind(cfg["port"])
            if hotkeys:
                hotkeys.start(cfg)
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            time.sleep(0.5)
            continue
        if not cfg.get("group_code"):
            continue
        msg = unpack(data, cfg["group_code"])
        if msg is None:
            try:
                raw = json.loads(data)
            except ValueError:
                continue
            if isinstance(raw, dict) and raw.get("probe"):
                n = str(raw["probe"])[:32]
                ok = hmac.compare_digest(_mac(cfg["group_code"], "probe:" + n), str(raw.get("proof", "")))
                reply = {"pong": n, "code_ok": ok, "ver": VERSION}
                if ok:
                    reply.update(id=cfg["device_id"], name=cfg["name"],
                                 knows_you=raw.get("from_id") in {d["id"] for d in cfg["devices"]},
                                 proof=_mac(cfg["group_code"], f"pong:{n}:{cfg['device_id']}"))
                sock.sendto(json.dumps(reply).encode(), addr)
                if not ok:
                    log.info("diagnostic probe from %s with a different group code", addr[0])
            elif isinstance(raw, dict) and raw.get("v") == 2 and "b" in raw:
                now = time.time()
                if now - wrong_code_logged.get(addr[0], 0) > 60:
                    wrong_code_logged[addr[0]] = now
                    log.warning("packet from %s with a different group code - ignored", addr[0])
            continue
        if msg.get("from_id") == cfg["device_id"]:
            continue
        kind, sender = msg.get("type"), msg.get("from_id")
        known = {d["id"]: d for d in cfg["devices"]}

        if sender in known and seen_ips.get(sender) != addr[0]:
            seen_ips[sender] = addr[0]
            try:
                SEEN_FILE.write_text(json.dumps(seen_ips))
            except OSError:
                pass

        if kind == "hello":
            here = pack({"type": "here", "from_id": cfg["device_id"], "from_name": cfg["name"],
                         "hostname": local_hostname(), "nonce": msg.get("nonce")}, cfg["group_code"])
            sock.sendto(here, addr)
            if addr[1] != cfg["port"]:      # also to their main port, in case a firewall drops the first
                sock.sendto(here, (addr[0], cfg["port"]))
        elif kind == "here":
            disc = {k: v for k, v in read_json(DISCOVERED_FILE, {}).items() if time.time() - v.get("t", 0) < 60}
            disc[sender] = {"id": sender, "name": msg.get("from_name", "?"), "host": msg.get("hostname") or addr[0],
                            "ip": addr[0], "nonce": msg.get("nonce"), "t": time.time()}
            try:
                DISCOVERED_FILE.write_text(json.dumps(disc))
            except OSError:
                pass
        elif kind == "alert":
            fresh = abs(time.time() - float(msg.get("ts", 0))) < MAX_AGE
            accepted = fresh and (sender in known or not cfg.get("only_my_devices", True))
            sock.sendto(pack({"type": "ack", "from_id": cfg["device_id"], "nonce": msg.get("nonce"),
                              "accepted": accepted}, cfg["group_code"]), addr)
            nonce = msg.get("nonce")
            if not accepted:
                log.info("ignored alert from unknown device %s (%s)", msg.get("from_name"), addr[0])
            elif nonce not in seen_nonces:
                seen_nonces[nonce] = time.time()
                who = known.get(sender, {}).get("name") or msg.get("from_name", "?")
                notify(str(msg.get("text", "Alert"))[:200], f"from {who}",
                       urgent=bool(msg.get("urgent")), sound=cfg.get("sound", True))
            if len(seen_nonces) > 1000:
                cut = time.time() - MAX_AGE
                seen_nonces = {k: v for k, v in seen_nonces.items() if v > cut}


def start_daemon_detached(exe_cmd):
    cfg = load_config()
    if port_in_use(cfg["port"]):
        return False
    args = shlex.split(exe_cmd, posix=not IS_WIN) + ["run"]
    kw = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "stdin": subprocess.DEVNULL}
    if IS_WIN:
        kw["creationflags"] = 0x00000008 | 0x00000200 | 0x08000000  # DETACHED|NEW_GROUP|NO_WINDOW
    else:
        kw["start_new_session"] = True
    subprocess.Popen(args, **kw)
    return True


def stop_daemon():
    stopped = False
    try:
        pid = int(PID_FILE.read_text())
        if IS_WIN:
            subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)
        else:
            os.kill(pid, 15)
        stopped = True
    except Exception:
        pass
    PID_FILE.unlink(missing_ok=True)
    if IS_LINUX and shutil.which("pkill"):   # old versions / copies started by hand
        r = subprocess.run(["pkill", "-u", str(os.getuid()), "-f", r"danger[-_]alert(\.py)? run$"],
                           env=clean_env(), capture_output=True)
        stopped = stopped or r.returncode == 0
    if stopped:
        time.sleep(0.5)                       # let the port be released
    return stopped


# ==================================================================== install
def install_path():
    if IS_WIN:
        return Path(os.environ.get("LOCALAPPDATA", Path.home())) / "DangerAlert" / "danger-alert.exe"
    return Path.home() / ".local/bin" / APP


def exe_command(copy=True):
    """Command line that launches this program, copying the binary to a stable place."""
    if not FROZEN:
        return f"{shlex.quote(sys.executable)} {shlex.quote(os.path.abspath(__file__))}"
    dst = install_path()
    src = Path(sys.executable).resolve()
    if copy and src != dst.resolve():
        dst.parent.mkdir(parents=True, exist_ok=True)
        tmp = dst.with_suffix(".new")
        shutil.copy2(src, tmp)
        os.replace(tmp, dst)            # works even while the old copy is running
        if not IS_WIN:
            os.chmod(dst, 0o755)
    return f'"{dst}"' if IS_WIN else shlex.quote(str(dst))


def install():
    cfg = load_config()
    if not CONFIG_FILE.exists():
        save_config(cfg)
    exe = exe_command()
    notes = []
    if IS_WIN:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "DangerAlert", 0, winreg.REG_SZ, f"{exe} run")
        notes.append("starts automatically at login")
    elif IS_LINUX:
        auto = Path.home() / ".config/autostart" / f"{APP}.desktop"
        auto.parent.mkdir(parents=True, exist_ok=True)
        auto.write_text(f"[Desktop Entry]\nType=Application\nName=Danger Alert\nExec={exe} run\n"
                        "NoDisplay=true\nX-GNOME-Autostart-enabled=true\nTerminal=false\n")
        menu = Path.home() / ".local/share/applications" / f"{APP}.desktop"
        menu.parent.mkdir(parents=True, exist_ok=True)
        menu.write_text(f"[Desktop Entry]\nType=Application\nName=Danger Alert Settings\n"
                        f"Comment=Configure devices, messages and hotkeys\nExec={exe} setup\n"
                        "Icon=dialog-warning\nTerminal=false\nCategories=Utility;\n")
        notes.append("starts automatically at login")
        notes.append("'Danger Alert Settings' added to the app menu")
    if hotkey_backend() == "gnome":
        n = gnome_set_shortcuts(cfg, exe)
        notes.append(f"{n} hotkeys registered as Ubuntu keyboard shortcuts")
    elif IS_LINUX and os.environ.get("XDG_SESSION_TYPE") == "wayland":
        notes.append("WARNING: non-GNOME Wayland desktop - bind your hotkeys manually to "
                     f"`{exe} send <id>` in your desktop's keyboard settings")
    else:
        notes.append("hotkeys handled by the background service")
    if IS_LINUX and ufw_enabled() and not cfg.get("ufw_allowed"):
        notes.append(f"FIREWALL is on: run `sudo ufw allow {cfg['port']}/udp` or alerts can't reach you")
    stop_daemon()                       # restart so a new binary/config is used
    time.sleep(0.3)
    started = start_daemon_detached(exe)
    notes.append("background service " + ("started" if started else "already running"))
    return notes


def uninstall():
    notes = []
    if gnome_ok():
        gnome_set_shortcuts({"messages": []}, None)
        notes.append("hotkeys removed")
    if IS_WIN:
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, "DangerAlert")
        except OSError:
            pass
    else:
        for p in (Path.home() / ".config/autostart" / f"{APP}.desktop",
                  Path.home() / ".local/share/applications" / f"{APP}.desktop"):
            p.unlink(missing_ok=True)
    notes.append("autostart removed")
    if stop_daemon():
        notes.append("background service stopped")
    notes.append(f"settings kept in {CONFIG_DIR} (delete it to remove everything)")
    return notes


# ======================================================================== GUI
def run_gui():
    import tkinter as tk
    from tkinter import ttk, messagebox, simpledialog

    cfg = load_config()
    if not cfg.get("group_code"):
        cfg["group_code"] = "-".join(secrets.token_hex(2) for _ in range(3))

    root = tk.Tk()
    root.title("Danger Alert - Settings")
    root.geometry("640x470")
    root.minsize(560, 420)
    style = ttk.Style(root)
    if "clam" in style.theme_names():
        style.theme_use("clam")
    # Worker threads must not touch Tk directly (with some Tk builds their calls are silently
    # lost), so they queue callbacks here and the main loop runs them.
    import queue
    ui_queue = queue.Queue()
    def ui(fn):
        ui_queue.put(fn)
    def pump():
        while True:
            try:
                fn = ui_queue.get_nowait()
            except queue.Empty:
                break
            try:
                fn()
            except Exception as e:
                log.error("ui callback failed: %s", e)
        root.after(80, pump)
    root.after(80, pump)

    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=10, pady=(10, 0))

    # ---------- tab: this device
    t1 = ttk.Frame(nb, padding=14)
    nb.add(t1, text="This device")
    v_name = tk.StringVar(value=cfg["name"])
    v_code = tk.StringVar(value=cfg["group_code"])
    v_port = tk.StringVar(value=str(cfg["port"]))
    v_sound = tk.BooleanVar(value=cfg.get("sound", True))
    v_confirm = tk.BooleanVar(value=cfg.get("confirm_sent", False))
    v_only = tk.BooleanVar(value=cfg.get("only_my_devices", True))

    def row(r, label, widget, hint=""):
        ttk.Label(t1, text=label).grid(row=r, column=0, sticky="w", pady=5)
        widget.grid(row=r, column=1, sticky="we", pady=5)
        if hint:
            ttk.Label(t1, text=hint, foreground="#777").grid(row=r, column=2, sticky="w", padx=8)
    t1.columnconfigure(1, weight=1)
    row(0, "Your name", ttk.Entry(t1, textvariable=v_name), "shown to friends")
    codef = ttk.Frame(t1)
    ttk.Entry(codef, textvariable=v_code).pack(side="left", fill="x", expand=True)
    ttk.Button(codef, text="New", width=5, command=lambda: v_code.set(
        "-".join(secrets.token_hex(2) for _ in range(3)))).pack(side="left", padx=(6, 0))
    v_check = tk.StringVar()
    v_code.trace_add("write", lambda *_: v_check.set(f"code check: {code_check(v_code.get())}"))
    v_check.set(f"code check: {code_check(v_code.get())}")
    ttk.Label(t1, textvariable=v_check, foreground="#a40").grid(row=1, column=2, sticky="w", padx=8)
    row(1, "Group code", codef)
    ttk.Label(t1, text="Every PC must show the same code check. Case and spaces don't matter.",
              foreground="#777").grid(row=8, column=0, columnspan=3, sticky="w", pady=(10, 0))
    row(2, "Port (UDP)", ttk.Entry(t1, textvariable=v_port, width=8), "same on every device")
    idv = ttk.Entry(t1)
    idv.insert(0, cfg["device_id"])
    idv.configure(state="readonly")
    row(3, "Your device ID", idv, "friends need this to add you")
    lanv = ttk.Entry(t1)
    lanv.insert(0, lan_ip())
    lanv.configure(state="readonly")
    row(9, "Your LAN address", lanv, "use this, not 172.x Docker IPs")
    ttk.Separator(t1).grid(row=4, column=0, columnspan=3, sticky="we", pady=10)
    ttk.Checkbutton(t1, text="Play a sound when an alert arrives", variable=v_sound).grid(
        row=5, column=0, columnspan=3, sticky="w")
    ttk.Checkbutton(t1, text="Show a tiny 'sent to N' confirmation on my screen when I send",
                    variable=v_confirm).grid(row=6, column=0, columnspan=3, sticky="w")
    ttk.Checkbutton(t1, text="Only accept alerts from devices in my list", variable=v_only).grid(
        row=7, column=0, columnspan=3, sticky="w")

    # ---------- tab: devices
    t2 = ttk.Frame(nb, padding=10)
    nb.add(t2, text="Devices")
    ttk.Label(t2, text="Only these devices get your alerts. For two-way alerts, each friend adds you too.\n"
                       "Scan finds devices running Danger Alert with the same group code + port "
                       "(save first if you changed them).",
              foreground="#555", wraplength=600).pack(anchor="w", pady=(0, 6))
    dev_tree = ttk.Treeview(t2, columns=("name", "host", "id"), show="headings", height=9)
    for c, w in (("name", 160), ("host", 260), ("id", 100)):
        dev_tree.heading(c, text=c.title())
        dev_tree.column(c, width=w)
    dev_tree.pack(fill="both", expand=True)
    devices = [dict(d) for d in cfg["devices"]]

    def refresh_devices():
        dev_tree.delete(*dev_tree.get_children())
        for d in devices:
            dev_tree.insert("", "end", iid=d["id"], values=(d["name"], d.get("host") or d.get("ip", ""), d["id"]))
    refresh_devices()
    dev_status = tk.StringVar()

    def current_cfg():
        c = dict(cfg)
        c.update(name=v_name.get().strip() or "Friend", group_code=v_code.get().strip(),
                 sound=v_sound.get(), confirm_sent=v_confirm.get(), only_my_devices=v_only.get(),
                 devices=devices, messages=messages)
        try:
            c["port"] = int(v_port.get())
        except ValueError:
            c["port"] = 50505
        return c

    def do_scan():
        dev_status.set("Scanning...")
        result = []
        def work():
            try:
                result.extend(scan(current_cfg()))
            finally:
                ui(done)
        def done():
            new = [f for f in result if f["id"] not in {d["id"] for d in devices}]
            dev_status.set(f"Found {len(result)} device(s), {len(new)} new.")
            if not new:
                return
            win = tk.Toplevel(root)
            win.title("Add devices")
            win.transient(root)
            ttk.Label(win, text="Select devices to add:", padding=8).pack(anchor="w")
            lb = tk.Listbox(win, selectmode="multiple", width=60, height=min(12, len(new)))
            for f in new:
                lb.insert("end", f"{f['name']}   ({f['host']}, {f['ip']})")
            lb.pack(padx=8, fill="both", expand=True)
            def add():
                for i in lb.curselection():
                    devices.append(new[i])
                refresh_devices()
                win.destroy()
            ttk.Button(win, text="Add selected", command=add).pack(pady=8)
        threading.Thread(target=work, daemon=True).start()

    def add_manual():
        name = simpledialog.askstring("Add device", "Friend's name:", parent=root)
        if not name:
            return
        host = simpledialog.askstring("Add device", "Hostname (e.g. alex-pc.local) or IP:", parent=root)
        if not host:
            return
        did = simpledialog.askstring("Add device", "Their device ID (in their 'This device' tab):", parent=root)
        if not did:
            return
        devices[:] = [d for d in devices if d["id"] != did.strip()]
        devices.append({"id": did.strip(), "name": name.strip(), "host": host.strip(), "ip": ""})
        refresh_devices()

    def remove_dev():
        sel = set(dev_tree.selection())
        devices[:] = [d for d in devices if d["id"] not in sel]
        refresh_devices()

    def test_dev():
        sel = dev_tree.selection()
        if not sel:
            dev_status.set("Select a device to test.")
            return
        dev_status.set("Sending test...")
        c = current_cfg()
        def work():
            try:
                r = send_alert(c, text=f"🔔 Test from {c['name']}", only=set(sel), quiet=True)
                tested = [d for d in devices if d["id"] in r]
                failed = [d for d in tested if r[d["id"]] != "ok"]
                if failed:
                    ui(lambda: dev_status.set("Some didn't confirm; checking why..."))
                why = {}
                seen = read_json(SEEN_FILE, {})
                ts = [threading.Thread(target=lambda d=d: why.__setitem__(d["id"], explain_device(c, d, seen)[1]),
                                       daemon=True) for d in failed]
                for t in ts:
                    t.start()
                for t in ts:
                    t.join(15)
                msg = "\n".join(f"✔ {d['name']}: received" if r[d["id"]] == "ok"
                                 else f"✘ {d['name']}: {why.get(d['id'], 'check timed out')}" for d in tested)
            except SystemExit as e:
                msg = str(e)
            ui(lambda: dev_status.set(msg))
        threading.Thread(target=work, daemon=True).start()

    bf = ttk.Frame(t2)
    bf.pack(fill="x", pady=6)
    for txt, cmd in (("Scan network", do_scan), ("Add manually...", add_manual),
                     ("Remove", remove_dev), ("Send test", test_dev), ("Diagnose", lambda: diagnose())):
        ttk.Button(bf, text=txt, command=cmd).pack(side="left", padx=(0, 6))
    ttk.Label(t2, textvariable=dev_status, foreground="#246", wraplength=600, justify="left").pack(anchor="w")

    # ---------- tab: messages
    t3 = ttk.Frame(nb, padding=10)
    nb.add(t3, text="Messages & hotkeys")
    msg_tree = ttk.Treeview(t3, columns=("id", "text", "hotkey", "urgent"), show="headings", height=10)
    for c, w in (("id", 90), ("text", 290), ("hotkey", 140), ("urgent", 60)):
        msg_tree.heading(c, text=c.title())
        msg_tree.column(c, width=w)
    msg_tree.pack(fill="both", expand=True)
    messages = [dict(m) for m in cfg["messages"]]

    def refresh_msgs():
        msg_tree.delete(*msg_tree.get_children())
        for i, m in enumerate(messages):
            msg_tree.insert("", "end", iid=str(i), values=(m["id"], m["text"], pretty_hotkey(m.get("hotkey", "")),
                                                           "yes" if m.get("urgent") else ""))
    refresh_msgs()

    def capture_hotkey(event, var):
        if event.keysym in ("Control_L", "Control_R", "Alt_L", "Alt_R", "Shift_L", "Shift_R",
                            "Super_L", "Super_R", "Meta_L", "Meta_R", "ISO_Level3_Shift"):
            return "break"
        if event.keysym in ("BackSpace", "Delete") and not event.state & 0x4:
            var.set("")
            return "break"
        mods = ""
        if event.state & 0x4: mods += "<Control>"
        if event.state & 0x8 or event.state & 0x80: mods += "<Alt>"
        if event.state & 0x1: mods += "<Shift>"
        if event.state & 0x40: mods += "<Super>"
        key = event.keysym.lower() if len(event.keysym) == 1 else event.keysym
        var.set(mods + key)
        return "break"

    def edit_msg(index=None):
        m = messages[index] if index is not None else {"id": "", "text": "", "hotkey": "", "urgent": False}
        win = tk.Toplevel(root)
        win.title("Message")
        win.transient(root)
        win.grab_set()
        f = ttk.Frame(win, padding=12)
        f.pack(fill="both", expand=True)
        f.columnconfigure(1, weight=1)
        vi, vt = tk.StringVar(value=m["id"]), tk.StringVar(value=m["text"])
        vh, vu = tk.StringVar(value=m.get("hotkey", "")), tk.BooleanVar(value=m.get("urgent", False))
        ttk.Label(f, text="ID (short)").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(f, textvariable=vi, width=20).grid(row=0, column=1, sticky="w")
        ttk.Label(f, text="Text").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(f, textvariable=vt, width=46).grid(row=1, column=1, sticky="we")
        ttk.Label(f, text="Hotkey").grid(row=2, column=0, sticky="w", pady=4)
        he = ttk.Entry(f, textvariable=vh, width=24)
        he.grid(row=2, column=1, sticky="w")
        he.bind("<KeyPress>", lambda e: capture_hotkey(e, vh))
        ttk.Label(f, text="Click the box and press the key combo (Backspace clears).\n"
                          "Use Ctrl/Alt/Super + a key. Avoid Ctrl+Alt+L/T/Delete (Ubuntu uses them).",
                  foreground="#777").grid(row=3, column=1, sticky="w")
        ttk.Checkbutton(f, text="Urgent (stays on screen, warning sound)", variable=vu).grid(
            row=4, column=1, sticky="w", pady=6)
        def ok():
            mid, txt = safe_id(vi.get() or vt.get()), vt.get().strip()
            if not txt:
                messagebox.showerror("Message", "Text is required.", parent=win)
                return
            hk = vh.get().strip()
            for j, o in enumerate(messages):
                if j != index and o["id"] == mid:
                    messagebox.showerror("Message", f"ID '{mid}' already used.", parent=win)
                    return
                if j != index and hk and o.get("hotkey") == hk:
                    messagebox.showerror("Message", f"Hotkey already used by '{o['id']}'.", parent=win)
                    return
            new = {"id": mid, "text": txt, "hotkey": hk, "urgent": vu.get()}
            if index is None:
                messages.append(new)
            else:
                messages[index] = new
            refresh_msgs()
            win.destroy()
        ttk.Button(f, text="OK", command=ok).grid(row=5, column=1, sticky="e")

    def sel_index():
        s = msg_tree.selection()
        return int(s[0]) if s else None

    mf = ttk.Frame(t3)
    mf.pack(fill="x", pady=6)
    ttk.Button(mf, text="Add...", command=lambda: edit_msg()).pack(side="left", padx=(0, 6))
    ttk.Button(mf, text="Edit...", command=lambda: sel_index() is not None and edit_msg(sel_index())).pack(
        side="left", padx=(0, 6))
    def rm_msg():
        i = sel_index()
        if i is not None:
            messages.pop(i)
            refresh_msgs()
    ttk.Button(mf, text="Remove", command=rm_msg).pack(side="left")
    msg_tree.bind("<Double-1>", lambda e: sel_index() is not None and edit_msg(sel_index()))

    # ---------- bottom bar
    bottom = ttk.Frame(root, padding=10)
    bottom.pack(fill="x")
    status = tk.StringVar(value=f"Background service: {'running' if port_in_use(cfg['port']) else 'not running'}")
    ttk.Label(bottom, textvariable=status, foreground="#246", wraplength=420).pack(side="left")

    def diagnose():
        win = tk.Toplevel(root)
        win.title("Danger Alert - Diagnose")
        win.geometry("760x420")
        txt = tk.Text(win, wrap="word", font=("TkFixedFont", 9))
        txt.pack(fill="both", expand=True, padx=8, pady=8)
        txt.insert("end", "Checking (takes ~10 seconds)...\n")
        c = current_cfg()
        def work():
            try:
                out = "\n".join(doctor(c))
            except Exception as e:
                out = f"Diagnosis failed: {e}"
            def show():
                txt.delete("1.0", "end")
                txt.insert("end", out + "\n\n(Ctrl+A, Ctrl+C to copy and share)")
            ui(show)
        threading.Thread(target=work, daemon=True).start()

    def maybe_open_firewall(c):
        if not (IS_LINUX and ufw_enabled()) or c.get("ufw_allowed"):
            return ""
        if not messagebox.askyesno("Firewall", f"The Ubuntu firewall is on and will block alerts.\n\n"
                                   f"Allow Danger Alert (UDP port {c['port']})? You'll be asked for your password."):
            return f"; firewall still blocks alerts (sudo ufw allow {c['port']}/udp)"
        r = subprocess.run(["pkexec", "ufw", "allow", f"{c['port']}/udp"], env=clean_env(),
                           capture_output=True, text=True)
        if r.returncode == 0:
            c["ufw_allowed"] = True
            save_config(c)
            return "; firewall opened"
        return f"; couldn't open firewall, run: sudo ufw allow {c['port']}/udp"

    def save_apply():
        c = current_cfg()
        if not c["group_code"]:
            messagebox.showerror("Danger Alert", "Group code can't be empty.")
            return
        cfg.clear()
        cfg.update(c)
        save_config(cfg)
        try:
            notes = install()
            status.set("Saved. " + "; ".join(notes) + maybe_open_firewall(cfg))
        except Exception as e:
            status.set(f"Saved, but setup step failed: {e}")
    ttk.Button(bottom, text="Close", command=root.destroy).pack(side="right")
    ttk.Button(bottom, text="Save & apply", command=save_apply).pack(side="right", padx=6)
    root.mainloop()


# ======================================================================= CLI
def main():
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    handlers = [logging.FileHandler(LOG_FILE, encoding="utf-8")]
    if sys.stderr and sys.stderr.isatty():
        handlers.append(logging.StreamHandler())
    logging.basicConfig(level=logging.INFO, handlers=handlers,
                        format="%(asctime)s %(levelname)s %(message)s")

    ap = argparse.ArgumentParser(prog=APP, description="Silent LAN alerts for your group of friends.")
    ap.add_argument("--version", action="version", version=VERSION)
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("setup", help="open the settings window")
    sub.add_parser("install", help="autostart + hotkeys + start background service")
    sub.add_parser("uninstall", help="remove autostart and hotkeys, stop service")
    sub.add_parser("run", help="run the background listener")
    sp = sub.add_parser("send", help="send a message")
    sp.add_argument("id", nargs="?", help="message id, e.g. danger")
    sp.add_argument("--text", help="custom text instead of a configured message")
    sub.add_parser("scan", help="find Danger Alert devices with your group code")
    ad = sub.add_parser("add-device", help="add a device manually")
    ad.add_argument("name"); ad.add_argument("host"); ad.add_argument("id")
    rd = sub.add_parser("remove-device", help="remove a device by id")
    rd.add_argument("id")
    sub.add_parser("devices", help="list configured devices")
    sub.add_parser("status", help="show status")
    sub.add_parser("doctor", help="find out why alerts/scan don't work")
    a = ap.parse_args()

    if a.cmd in (None, "setup"):
        try:
            run_gui()
        except Exception as e:      # no display / no tkinter
            if a.cmd is None:
                ap.print_help()
            print(f"\nSettings window unavailable ({e}). Edit {CONFIG_FILE} or use the CLI.")
    elif a.cmd == "run":
        run_daemon()
    elif a.cmd == "install":
        print("\n".join("• " + n for n in install()))
    elif a.cmd == "uninstall":
        print("\n".join("• " + n for n in uninstall()))
    elif a.cmd == "send":
        if not (a.id or a.text):
            sp.error("give a message id or --text")
        # cooldown shared across processes (GNOME shortcut launches a new one each time)
        try:
            if time.time() - LAST_SEND_FILE.stat().st_mtime < COOLDOWN:
                return
        except OSError:
            pass
        LAST_SEND_FILE.touch()
        r = send_alert(load_config(), msg_id=a.id, text=a.text)
        if sys.stdout and sys.stdout.isatty():
            for k, v in r.items():
                print(f"{k}: {v}")
    elif a.cmd == "scan":
        cfg = load_config()
        if not cfg.get("group_code"):
            raise SystemExit("Set a group code first (danger-alert setup).")
        found = scan(cfg)
        mine = {d["id"] for d in cfg["devices"]}
        for f in found:
            print(f"{f['name']:<16} {f['host']:<28} {f['ip']:<16} id={f['id']}"
                  + ("  (in your list)" if f["id"] in mine else ""))
        print(f"{len(found)} device(s) found.")
    elif a.cmd == "add-device":
        cfg = load_config()
        cfg["devices"] = [d for d in cfg["devices"] if d["id"] != a.id]
        cfg["devices"].append({"id": a.id, "name": a.name, "host": a.host, "ip": ""})
        save_config(cfg)
        print(f"Added {a.name}.")
    elif a.cmd == "remove-device":
        cfg = load_config()
        cfg["devices"] = [d for d in cfg["devices"] if d["id"] != a.id]
        save_config(cfg)
        print("Removed.")
    elif a.cmd == "devices":
        for d in load_config()["devices"]:
            print(f"{d['name']:<16} {d.get('host') or d.get('ip', ''):<28} id={d['id']}")
    elif a.cmd == "doctor":
        cfg = load_config()
        if not cfg.get("group_code"):
            raise SystemExit("No group code set yet. Run `danger-alert setup` first.")
        print("Checking (takes ~10 seconds)...\n")
        print("\n".join(doctor(cfg)))
    elif a.cmd == "status":
        cfg = load_config()
        print(f"Danger Alert {VERSION}")
        print(f"Config:     {CONFIG_FILE}{'' if CONFIG_FILE.exists() else ' (not created yet)'}")
        print(f"Log:        {LOG_FILE}")
        print(f"Me:         {cfg['name']}  id={cfg['device_id']}  port={cfg['port']}")
        print(f"Code check: {code_check(cfg['group_code'])}  (must match on every PC)")
        print(f"LAN address: {lan_ip()}")
        print(f"Service:    {'running' if port_in_use(cfg['port']) else 'not running'}")
        print(f"Hotkeys:    {hotkey_backend()}")
        print(f"Devices:    {len(cfg['devices'])}")
        for m in cfg["messages"]:
            print(f"  {pretty_hotkey(m.get('hotkey')) or '(no hotkey)':<20} {m['id']:<10} {m['text']}")


if __name__ == "__main__":
    main()
