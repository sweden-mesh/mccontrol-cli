#!/usr/bin/env python3
"""Screenshots of each interface, from an invented fleet: `python scripts/screenshots.py`.

Builds a scratch home (never ~/.config/mccontrol) with ten invented repeaters -- names, keys,
regions and firmware made up here, checked against the real fleet's keys in the test data --
with a history, reads, command sets and a Beacon statistics series, all served through the fake
transport and the fake Beacon the tests use. It is a lou-20 fleet: most nodes found by their alive
message and kept without a region, one without Wi-Fi reached through a relay, one on lou-18. Each interface runs in a pseudo-terminal and is
driven through a few states; the screen is kept by a small colour terminal emulator, written
out as HTML in the interface's own colours, and headless Chromium turns that into
`docs/screenshots/<interface>-<state>.png`. Two command lines are run over the same home and
drawn the same way (`cli-<what>.png`). Rerun it when the screens change.

    python scripts/screenshots.py [--only monolith-board] [--out docs/screenshots] [--keep-html]
"""

import argparse
import codecs
import fcntl
import hashlib
import html
import json
import os
import pathlib
import pty
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import ptywalk                                  # noqa: E402  (tests/ptywalk.py: waiting on a curses program)
from mccontrol import store as _store           # noqa: E402

# -- the invented fleet -----------------------------------------------------------------

HOMES = ("se-zqv", "se-zqw")                                 # invented region homes, as the nodes' alive names them
OLD_REGION = "ZQV"                                           # the one IATA left: not a code the real fleet uses
RELAY, NO_WIFI = "Quarry-Hill", "Allotments"                 # the node without Wi-Fi is reached through the relay
# A lou-20 fleet: most nodes found by their alive message, with no region (`alive`); one on a
# board without Wi-Fi, added by its key and reached over the mesh (`mesh`); one still on lou-18
# and the old per-region scheme (`old`).
FLEET = [  # name, region home, kind, battery mV, tx delay
    ("Lighthouse-North", "se-zqv", "alive", 4180, "0.7"), ("Old-Mill", "se-zqv", "alive", 3920, "0.5"),
    ("Water-Tower", "se-zqv", "old", 4105, "1.0"), ("Church-Spire", "se-zqv", "alive", 3870, "0.5"),
    ("Ridge-East", "se-zqv", "alive", 4240, "0.8"), ("Harbour", "se-zqv", "alive", 3995, "0.5"),
    ("Quarry-Hill", "se-zqw", "alive", 4060, "0.6"), ("Allotments", "se-zqw", "mesh", 3760, "0.5"),
    ("Fire-Station", "se-zqw", "alive", 4150, "0.9"), ("School-Roof", "se-zqw", "alive", 4010, "0.5"),
]


def key_of(name):
    return hashlib.sha256(f"mccontrol-screenshot {name}".encode()).hexdigest().upper()


def firmware(name, kind):
    # The released images: the Observer one with auto-reply and the plane, the one for a board
    # without Wi-Fi (the plane, no Observer bridge), and lou-18 on the node that lags.
    lou, flavour = {"alive": (20, "arrc-observer"), "mesh": (20, "rc"), "old": (18, "arrc-observer")}[kind]
    board = "rak4631" if kind == "mesh" else "esp32s3"
    return f"{board}-v1.18.0-lou-{lou}-{flavour}-{hashlib.sha256(name.encode()).hexdigest()[:7]}"


def check_invented():
    """None of the invented keys may share a prefix with a real node's key."""
    real = json.loads((ROOT / "tests" / "data" / "beacon-fake.json").read_text())["/nodes"]["items"]
    prefixes = {n["publicKey"][:6].upper() for n in real}
    clash = [n for n, *_ in FLEET if key_of(n)[:6] in prefixes]
    if clash:
        raise SystemExit(f"invented keys clash with the real fleet: {clash}")


def at(days, hour=9, minute=0):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - days * 86400 + (hour - 12) * 3600 + minute * 60))


def build_home(where):
    """The scratch home, the fake broker's script and the fake Beacon's table."""
    from mccontrol import actions
    home = where / "home"
    st = _store.Store(home)
    st.create_key()
    # a configured install: an invented broker, the key registered with it and a passing broker
    # test, kept as `register` and `test` keep them; nothing reaches it (the fake broker answers)
    st.save_config(broker="mqtt.example.org", port=8883, tls=True, beacon_url="http://beacon.example.org", wait_secs=4,
                   sets={"add-scope": ["region put {arg} *", "region allowf {arg}", "region save", "region"],
                         "audit": ["ver", "get txdelay", "get cmd"]})
    st.remember_registration("mqtt.example.org")
    st.remember_test("mqtt.example.org", 8883, True)
    (home / "history").mkdir(exist_ok=True)
    script, nodes, table = {}, [], {}
    relay = {"node": key_of(RELAY)[:8], "name": RELAY, "route": "direct", "status": "answered", "sent": "direct", "snr": 5.5}
    for i, (name, region_home, kind, mv, txdelay) in enumerate(FLEET):
        key = key_of(name)
        node = key[:8]
        ver = firmware(name, kind)
        observer = None if kind == "mesh" else f"00000000-0000-4000-8000-{i:012d}"
        counter = int(time.time()) - 86400 + 60 * i
        if kind == "alive":         # as discovery keeps a node whose alive message opened: its key, no region
            fields = {"boot": 3 + i, "sequence": 40 + i, "uptime": 1209600 + i * 3600, "clock": int(time.time()) - 600,
                      "last_counter": counter, "interval": 900, "flags": 0x01 | 0x10, "mesh": 2,
                      "fingerprint": st.public_key()[:8], "version": ver, "region": region_home, "name": name}
            actions.adopt(st, {"node": key, "key": key, "region": "",
                               "alive": actions._alive_record(fields, "online", time.time() - 600)}, name)
        else:                       # added by hand: by its key alone, or with the IATA the old scheme needs
            st.add_device(name, key, OLD_REGION if kind == "old" else "", key=key)
        heard = {"mesh": "last_heard_relay"}.get(kind, "last_heard_mqtt")
        st.update_device(node, ver=ver, observer_id=observer, last_sent=at(i % 4, 10 + i), last_result="ok",
                         last_heard=at(i % 4, 10 + i), **{heard: at(i % 4, 10 + i)},
                         **({} if kind == "mesh" else {"fleet": {"battery_mv": mv, "seen": at(0, 11), "at": at(0, 11)}}))
        topic = f"meshcore/{OLD_REGION}/{key}/cmd" if kind == "old" else f"mcc/cmd/{key}"
        road = {"road": "relay", "relay": relay, "note": ""} if kind == "mesh" else \
               {"road": "mqtt", "note": "" if kind == "old" else "mcc3"}
        lines = [(at(5 + i % 3, 9), "ver", f"> {ver}", True),
                 (at(3, 10, i), "get txdelay", f"> {txdelay}", True),
                 (at(1, 16, i), "region", f"> * F\n {region_home} F", True)]
        if kind == "old":           # the old scheme: auto-reply on the region's own test channel
            lines.insert(2, (at(2, 14, i), "get autoreply", f"> on #test-{OLD_REGION.lower()} 'test' max 8 hops, direct flood, "
                                                           f"mode flood, private off", True))
        else:                       # what lou-20 brought: the plane's own line, and relaying
            mesh = "mesh only, mesh on" if kind == "mesh" else "mesh on"
            lines.insert(2, (at(2, 14, i), "get cmd", f"> on, counter {counter}, {mesh} ok {2 + i % 3} refused 0", True))
        if kind == "alive":
            lines.append((at(1, 16, 30 + i), "get relay", f"> own, forwarded {i % 4}, answered {i % 4}, refused 0", True))
        if name == "Old-Mill":
            lines.append((at(0, 9, 5), "set txdelay 0.5", "OK", True))
        if name == "Church-Spire":                          # someone else signing in its name
            lines.append((at(0, 8, 30), "get name", "> Totally-Legit", False))
        with (home / "history" / f"{node}.jsonl").open("w") as f:
            for when, command, reply, signed in lines:
                f.write(json.dumps({"at": when, "command": command, "topic": topic, "code": 0, "code_name": "ok",
                                    "reply": reply, "verified": signed, **road}) + "\n")
        devs = json.loads((home / "devices.json").read_text())
        entry = next(d for d in devs if d["node"] == node)
        entry["reads"] = {c: {"reply": r, "at": w, "seq": n, "verified": s}
                          for n, (w, c, r, s) in enumerate(lines) if s is not False and not c.startswith("set ")}
        entry["reads"]["neighbors"] = {"reply": "> 3 neighbours", "at": at(1, 8), "seq": 9, "verified": True}
        (home / "devices.json").write_text(json.dumps(devs, indent=2))
        script[node] = [0, "> * F"]
        script[f"{node}|ver"] = [0, f"> {ver}"]
        script[f"{node}|get name"] = [0, f"> {name}"]
        script[f"{node}|get txdelay"] = [0, f"> {txdelay}"]
        script[f"{node}|get rxdelay"] = [0, "> 0.0"]
        script[f"{node}|get cmd"] = [0, lines[2][2] if kind != "old" else "> on"]
        script[f"{node}|get stats"] = [0, '> {"batt":%d,"up":1209600,"nf":-114}' % mv]
        if observer is None:        # no Wi-Fi: not an observer, so Beacon has no status for it
            continue
        iata = OLD_REGION if kind == "old" else "ZQX"       # the Observer feed's own setting, not the plane's
        nodes.append({"id": f"node-{i}", "publicKey": key.lower(), "nodeType": 2, "nodeTypeName": "repeater", "name": name,
                      "isObserver": True, "observerId": observer, "iatas": [{"iata": iata, "lastHeard": int(time.time() * 1000)}]})
        table[f"/observers/{observer}"] = {
            "id": observer, "displayName": name, "observerType": f"meshcore/{ver}", "iata": iata, "status": "online",
            "statusMetadata": {"model": "Heltec V3", "radio": "869.617981,62.5,8,5", "repeat": "on", "status": "online",
                               "firmware_version": ver, "stats": {
                                   "errors": i, "queue_len": 0, "battery_mv": mv, "noise_floor": -114 + i % 3,
                                   "recv_errors": 900 + 37 * i, "rx_air_secs": 20000 + 811 * i, "tx_air_secs": 4000 + 97 * i,
                                   "uptime_secs": 1209600 + i * 3600, "packets_sent": 8000 + 123 * i,
                                   "internal_heap": 117000, "packets_received": 40000 + 1009 * i}},
            "publicKey": key.lower(), "firmwareVersion": ver, "hardwareModel": "Heltec V3", "radioFreqMhz": 869.618,
            "radioSf": 8, "radioBwKhz": 62.5, "radioCr": 5, "batteryLevel": mv / 1000, "uptimeSeconds": 1209600 + i * 3600,
            "noiseFloorDb": -114 + i % 3, "lastSeen": int(time.time() * 1000) - 600000, "lastStatusAt": int(time.time() * 1000) - 600000}
        now = int(time.time() * 1000)
        table[f"/observers/{observer}/telemetry"] = {"range": "24h", "interval": "6h", "points": [
            {"t": now - (8 - n) * 3 * 3600000, "batteryMv": mv - 120 + (n * 37 % 160), "airtimeTxSecs": 20 + n * 9 % 50,
             "airtimeRxSecs": 90 + n * 31 % 200, "noiseFloorDb": -116 + n % 4, "uptimeSeconds": 1200000 + n * 10800,
             "queueLength": 0, "receiveErrors": 30 + n * 17 % 90} for n in range(9)]}
    table["/nodes"] = {"items": nodes}
    beacon = where / "beacon.json"
    beacon.write_text(json.dumps(table))
    return home, script, beacon


# -- a terminal that keeps colour -------------------------------------------------------

ACS = str.maketrans("qxlkmjtuvwna`", "─│┌┐└┘├┤┴┬┼▒◆")


class Screen:
    """Enough of an xterm to keep what curses draws, colour and attributes too: cursor moves,
    erases (in the current background), inserts and insert mode, deletes, scrolling, the
    deferred wrap at the right margin, SGR, the ACS charset."""

    CSI = re.compile(r"\x1b\[([?>=]?)([0-9;:]*)([A-Za-z@`])")
    OTHER = re.compile(r"\x1b(\][^\x07\x1b]*(?:\x07|\x1b\\)|[()][0-9A-B]|[78=>MDEc])")

    def __init__(self, cols, rows):
        self.cols, self.rows = cols, rows
        self.pen = (None, None, False, False, False, False)          # fg, bg, bold, dim, underline, reverse
        self.grid = [[(" ", self.pen)] * cols for _ in range(rows)]
        self.y = self.x = self.top = 0
        self.bottom, self.last, self.pending, self.acs, self.saved = rows - 1, (" ", self.pen), "", False, (0, 0)
        self.insert = False                                           # IRM, which curses uses to shift a line

    def blank(self):
        return (" ", (None, self.pen[1], False, False, False, False))

    def _scroll(self, at, up=True):
        if up:
            del self.grid[at]
            self.grid.insert(self.bottom, [self.blank()] * self.cols)
        else:
            del self.grid[self.bottom]
            self.grid.insert(at, [self.blank()] * self.cols)

    def feed(self, data):
        data, self.pending, i = self.pending + data, "", 0
        while i < len(data):
            c = data[i]
            if c == "\x1b":
                m = self.CSI.match(data, i) or self.OTHER.match(data, i)
                if not m:
                    self.pending = data[i:]
                    return
                i = m.end()
                if m.re is self.CSI:
                    if not m.group(1):
                        args = [int(v) if v.isdigit() else 0 for v in re.split("[;:]", m.group(2))] if m.group(2) else []
                        self._csi(args, m.group(3))
                    continue
                seq = m.group(1)
                if seq == "M":
                    self._scroll(self.top, up=False) if self.y == self.top else setattr(self, "y", self.y - 1)
                elif seq in ("(0", "(B"):
                    self.acs = seq == "(0"
                elif seq == "7":
                    self.saved = (self.y, self.x)
                elif seq == "8":
                    self.y, self.x = self.saved
                continue
            i += 1
            if c == "\r":
                self.x = 0
            elif c == "\n":
                self._scroll(self.top) if self.y == self.bottom else setattr(self, "y", min(self.rows - 1, self.y + 1))
            elif c == "\b":
                self.x = max(0, self.x - 1)
            elif c >= " ":
                if self.acs:
                    c = c.translate(ACS)
                if self.x >= self.cols:                     # xterm's deferred wrap: only now to the next line
                    self.x = 0
                    self._scroll(self.top) if self.y == self.bottom else setattr(self, "y", min(self.rows - 1, self.y + 1))
                self.last = (c, self.pen)
                if self.insert:
                    self.grid[self.y].insert(self.x, self.last)
                    del self.grid[self.y][self.cols:]
                else:
                    self.grid[self.y][self.x] = self.last
                self.x += 1

    def _sgr(self, a):
        fg, bg, bold, dim, ul, rev = self.pen
        a = a or [0]
        n = 0
        while n < len(a):
            v = a[n]
            if v == 0:
                fg, bg, bold, dim, ul, rev = None, None, False, False, False, False
            elif v == 1:
                bold = True
            elif v == 2:
                dim = True
            elif v == 4:
                ul = True
            elif v == 7:
                rev = True
            elif v == 22:
                bold = dim = False
            elif v == 24:
                ul = False
            elif v == 27:
                rev = False
            elif 30 <= v <= 37:
                fg = v - 30
            elif 90 <= v <= 97:
                fg = v - 90 + 8
            elif 40 <= v <= 47:
                bg = v - 40
            elif 100 <= v <= 107:
                bg = v - 100 + 8
            elif v == 39:
                fg = None
            elif v == 49:
                bg = None
            elif v in (38, 48) and n + 2 < len(a) and a[n + 1] == 5:
                fg, bg = (a[n + 2], bg) if v == 38 else (fg, a[n + 2])
                n += 2
            n += 1
        self.pen = (fg, bg, bold, dim, ul, rev)

    def _csi(self, a, f):
        n = a[0] if a and a[0] else 1
        row = self.grid[self.y]
        if f == "m":
            self._sgr(a)
        elif f in "hl":
            if 4 in a:
                self.insert = f == "h"
        elif f in "Hf":
            self.y = min(self.rows - 1, n - 1)
            self.x = min(self.cols - 1, (a[1] if len(a) > 1 and a[1] else 1) - 1)
        elif f in "ABCD":
            self.y = max(0, min(self.rows - 1, self.y + {"A": -n, "B": n}.get(f, 0)))
            self.x = max(0, min(self.cols - 1, self.x + {"C": n, "D": -n}.get(f, 0)))
        elif f in "G`":
            self.x = min(self.cols - 1, n - 1)
        elif f == "d":
            self.y = min(self.rows - 1, n - 1)
        elif f == "K":
            mode = a[0] if a else 0
            lo, hi = {0: (self.x, self.cols), 1: (0, self.x + 1)}.get(mode, (0, self.cols))
            row[lo:hi] = [self.blank()] * (hi - lo)
        elif f == "J":
            mode = a[0] if a else 0
            if mode == 0:
                row[self.x:] = [self.blank()] * (self.cols - self.x)
            for r in (range(self.rows) if mode == 2 else range(self.y + 1, self.rows) if mode == 0 else ()):
                self.grid[r] = [self.blank()] * self.cols
        elif f == "X":
            row[self.x:self.x + n] = [self.blank()] * len(row[self.x:self.x + n])
        elif f == "P":
            del row[self.x:self.x + n]
            row += [self.blank()] * (self.cols - len(row))
        elif f == "@":
            row[self.x:self.x] = [self.blank()] * n
            del row[self.cols:]
        elif f == "b":
            for _ in range(n):
                if self.x < self.cols:
                    row[self.x] = self.last
                    self.x += 1
        elif f == "r":
            self.top, self.bottom = n - 1, (a[1] if len(a) > 1 and a[1] else self.rows) - 1
            self.y = self.x = 0
        elif f in "LM":
            for _ in range(n):
                self._scroll(self.y, up=f == "M")
        elif f == "S":
            for _ in range(n):
                self._scroll(self.top)
        elif f == "T":
            for _ in range(n):
                self._scroll(self.top, up=False)


# -- the picture ------------------------------------------------------------------------

BASE16 = ["#000000", "#cd0000", "#00cd00", "#cdcd00", "#0000ee", "#cd00cd", "#00cdcd", "#e5e5e5",
          "#7f7f7f", "#ff0000", "#00ff00", "#ffff00", "#5c5cff", "#ff00ff", "#00ffff", "#ffffff"]
DEFAULT_FG, DEFAULT_BG = "#d0d0d0", "#000000"


def colour(n):
    if n is None:
        return None
    if n < 16:
        return BASE16[n]
    if n < 232:
        n -= 16
        steps = [0, 95, 135, 175, 215, 255]
        return "#%02x%02x%02x" % (steps[n // 36], steps[n // 6 % 6], steps[n % 6])
    v = 8 + (n - 232) * 10
    return "#%02x%02x%02x" % (v, v, v)


def to_html(screen, title):
    rows = []
    for line in screen.grid:
        out, run, style = [], [], None
        for ch, (fg, bg, bold, dim, ul, rev) in line:
            f, b = colour(fg + 8 if bold and fg is not None and fg < 8 else fg) or DEFAULT_FG, colour(bg) or DEFAULT_BG
            if rev:
                f, b = b, f
            css = f"color:{f};background:{b}" + (";font-weight:bold" if bold else "") + (";opacity:.6" if dim and not rev else "") \
                + (";text-decoration:underline" if ul else "")
            if css != style and run:
                out.append(f'<span style="{style}">{html.escape("".join(run))}</span>')
                run = []
            style = css
            run.append(ch)
        if run:
            out.append(f'<span style="{style}">{html.escape("".join(run))}</span>')
        rows.append("".join(out))
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title><style>"
            f"html,body{{margin:0;background:{DEFAULT_BG}}}"
            "pre{margin:0;padding:8px;font:15px/18px 'DejaVu Sans Mono',monospace;font-variant-ligatures:none}"
            "span{display:inline}</style></head><body><pre>" + "\n".join(rows) + "</pre></body></html>")


def to_png(html_path, png_path, cols, rows):
    browser = shutil.which("chromium") or shutil.which("google-chrome") or shutil.which("chromium-browser")
    if not browser:
        raise SystemExit("no headless chromium on this host")
    width, height = int(cols * 9.04) + 16, rows * 18 + 16
    subprocess.run([browser, "--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
                    f"--window-size={width},{height}", f"--screenshot={png_path}", html_path.as_uri()],
                   check=True, capture_output=True, timeout=120)


# -- driving an interface ---------------------------------------------------------------

DOWN, UP, ENTER, TAB, ESC = b"\x1bOB", b"\x1bOA", b"\r", b"\t", b"\x1b"


def capture(ui, cols, rows, keys, home, script, beacon, wait=0.6, after=0.0):
    """Run `ui` over the scratch home in a pty of `cols` x `rows`, type `keys` -- `(bytes,
    seconds at most)` -- and return the screen as it stands `after` seconds later."""
    pid, fd = pty.fork()
    if pid == 0:
        fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        os.environ.update(TERM="xterm-256color", COLUMNS=str(cols), LINES=str(rows), MCCONTROL_HOME=str(home),
                          MCCONTROL_FAKE_RESULTS=json.dumps(script), MCCONTROL_FAKE_BEACON=str(beacon),
                          MCCONTROL_FAKE_WAIT=str(wait), LANG="C.UTF-8", LC_ALL="C.UTF-8")
        os.execvp(sys.executable, [sys.executable, "-c", "import sys; sys.path.insert(0, %r); from mccontrol import cli; "
                                   "sys.exit(cli.main(['--ui', %r]))" % (str(ROOT), ui)])
    screen, decode = Screen(cols, rows), codecs.getincrementaldecoder("utf-8")("replace")

    screen.raw = b""

    def sink(data):
        screen.raw += data
        screen.feed(decode.decode(data))
    ptywalk.settle(fd, pid, 3.0, sink)
    for k, limit in keys:
        ptywalk.key(fd, pid, k, limit, sink)
    if not after:                       # Ctrl+L: every interface draws the whole screen again, so the
        ptywalk.key(fd, pid, b"\x0c", 1.0, sink)     # picture never depends on how curses chose to update it
    end = time.time() + after
    while time.time() < end:
        ptywalk.settle(fd, pid, max(0.05, end - time.time()), sink)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    os.waitpid(pid, 0)
    return screen


# (file name, interface, cols, rows, keys, fake wait, seconds after the keys)
STATES = [
    ("monolith-summary", "Monolith", 80, 24, [(DOWN, 0.4)], 0.6, 0),
    ("monolith-board", "Monolith", 120, 40, [(DOWN, 0.4), (b":", 0.6), (b"stat 24", 0.4), (ENTER, 3.0)], 0.6, 0),
    ("monolith-commands", "Monolith", 120, 40, [(DOWN, 0.4), (ENTER, 0.8)], 0.6, 0),
    ("monolith-sending", "Monolith", 120, 40, [(DOWN, 0.4), (TAB * 3, 0.4), (b"get txdelay", 0.4), (ENTER, 0.3)], 8.0, 2.5),
    ("monolith-command-line", "Monolith", 120, 40, [(DOWN, 0.4), (TAB * 3, 0.4), (b"get txdelay", 0.4), (ENTER, 2.5),
                                                    (b"get rxdelay", 0.4), (ENTER, 2.5)], 0.6, 0),
    ("meshcorecommander-summary", "MeshcoreCommander", 80, 24, [(DOWN, 0.4)], 0.6, 0),
    ("meshcorecommander-board", "MeshcoreCommander", 120, 40, [(DOWN, 0.4), (TAB * 3, 0.4), (b"get txdelay", 0.4),
                                                               (ENTER, 2.5)], 0.6, 0),
    ("meshcorecommander-commands", "MeshcoreCommander", 120, 40, [(DOWN, 0.4), (ENTER, 0.8)], 0.6, 0),
    ("meshcorecommander-history", "MeshcoreCommander", 120, 40, [(b"h", 0.8)], 0.6, 0),
    ("meshcorecommander-sending", "MeshcoreCommander", 120, 40, [(DOWN, 0.4), (b"\x1bOQ", 0.6), (b"get txdelay", 0.3),
                                                                 (ENTER, 0.3)], 8.0, 2.5),
    ("ibmi-summary", "IBMi", 80, 24, [], 0.6, 0),
    ("ibmi-devices", "IBMi", 120, 40, [(b"1\r", 0.8)], 0.6, 0),
    ("ibmi-facts", "IBMi", 120, 40, [(b"1\r", 0.8), (DOWN, 0.2), (b"8\r", 0.8)], 0.6, 0),
    ("ibmi-command-entry", "IBMi", 120, 40, [(b"1\r", 0.8)] + [(DOWN, 0.2), (b"1", 0.2)] * 4 + [
        (ENTER, 0.6), (b"cmd\r", 0.6), (b"get txdelay\r", 2.5), (b"ver\r", 2.5)], 0.3, 0),   # four waits fit the 2.5 s
    ("ibmi-history", "IBMi", 120, 40, [(b"12\r", 1.0)], 0.6, 0),
]


# -- the command line ---------------------------------------------------------------------

MCCONTROL = ["-c", "import sys; from mccontrol import cli; sys.exit(cli.main(sys.argv[1:]))"]


def rotation(home):
    """A key rotation under way in the scratch home: a next key (invented here, like the first),
    most nodes on it, one offered and not yet confirmed, the rest still to do."""
    from mccontrol import rekey
    st = _store.Store(home)
    rekey.start(st)
    for name, state in [("Lighthouse-North", rekey.NEW), ("Old-Mill", rekey.NEW), ("Church-Spire", rekey.NEW),
                        ("Harbour", rekey.NEW), ("Allotments", rekey.NEW), ("Ridge-East", rekey.OFFERED)]:
        rekey._set_state(st, key_of(name)[:8], state)


# (file name, columns, what to do to the home first, the command lines as typed and as run)
CLI_STATES = [
    ("cli-rekey-status", 100, rotation, [("python -m mccontrol.rekey status", ["-m", "mccontrol.rekey", "status"])]),
    ("cli-relay-send", 100, None, [
        (f"mccontrol send {NO_WIFI.lower()} ver --via relay:{RELAY.lower()}",
         MCCONTROL + ["send", NO_WIFI.lower(), "ver", "--via", f"relay:{RELAY.lower()}"]),
        (f"mccontrol send {NO_WIFI.lower()} get cmd --via relay:{RELAY.lower()} --route flood",
         MCCONTROL + ["send", NO_WIFI.lower(), "get", "cmd", "--via", f"relay:{RELAY.lower()}", "--route", "flood"])]),
]


def capture_cli(commands, cols, home, script, beacon):
    """Run each command line over the scratch home and return the screen a terminal `cols`
    wide would show: a prompt with the line as typed, then what it printed."""
    env = dict(os.environ, MCCONTROL_HOME=str(home), MCCONTROL_FAKE_RESULTS=json.dumps(script),
               MCCONTROL_FAKE_BEACON=str(beacon), MCCONTROL_FAKE_WAIT="0", LANG="C.UTF-8", LC_ALL="C.UTF-8")
    shown = []
    for typed, argv in commands:
        done = subprocess.run([sys.executable] + argv, cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
        shown.append((typed, done.stdout.rstrip("\n").split("\n")))
    rows = sum(1 + sum(max(1, -(-len(line) // cols)) for line in out) for _typed, out in shown) + len(shown) - 1
    screen = Screen(cols, rows)
    screen.feed("\r\n\r\n".join(f"\x1b[1;32m$\x1b[0;1m {typed}\x1b[0m\r\n" + "\r\n".join(out) for typed, out in shown))
    return screen


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--out", default=str(ROOT / "docs" / "screenshots"))
    p.add_argument("--only", action="append", help="a state's file name (without .png); repeatable")
    p.add_argument("--keep-html", action="store_true", help="write the HTML beside each PNG")
    args = p.parse_args(argv)
    check_invented()
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mccontrol-shots-") as tmp:
        for name, ui, cols, rows, keys, wait, after in STATES:
            if args.only and name not in args.only:
                continue
            where = pathlib.Path(tmp) / name
            where.mkdir()
            home, script, beacon = build_home(where)        # a fresh home each: no state leaks between pictures
            screen = capture(ui, cols, rows, keys, home, script, beacon, wait, after)
            page = (out if args.keep_html else where) / f"{name}.html"
            page.write_text(to_html(screen, f"mccontrol {ui}"), encoding="utf-8")
            to_png(page, out / f"{name}.png", cols, rows)
            print(f"{out / name}.png  {cols}x{rows}")
        for name, cols, prepare, commands in CLI_STATES:
            if args.only and name not in args.only:
                continue
            where = pathlib.Path(tmp) / name
            where.mkdir()
            home, script, beacon = build_home(where)
            if prepare:
                prepare(home)
            screen = capture_cli(commands, cols, home, script, beacon)
            page = (out if args.keep_html else where) / f"{name}.html"
            page.write_text(to_html(screen, name), encoding="utf-8")
            to_png(page, out / f"{name}.png", cols, screen.rows)
            print(f"{out / name}.png  {cols}x{screen.rows}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
