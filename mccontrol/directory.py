"""The device directory as rows: what the left panel shows, computed from the store."""

import datetime

SORTS = ("name", "region", "last sent")


def relative(when, now=None):
    """`2 h`, `3 d`, `now`, or `-` for never: the age of an ISO timestamp, short enough for a column."""
    if not when:
        return "-"
    try:
        then = datetime.datetime.fromisoformat(when)
    except ValueError:
        return "?"
    now = now or datetime.datetime.now()
    secs = max(0, int((now - then).total_seconds()))
    if secs < 60:
        return "now"
    if secs < 3600:
        return f"{secs // 60} min"
    if secs < 86400:
        return f"{secs // 3600} h"
    return f"{secs // 86400} d"


def sorted_devices(devices, by="name"):
    if by == "region":
        return sorted(devices, key=lambda d: ((d.get("region") or "").upper(), (d.get("name") or "~" + d["node"]).lower()))
    if by == "last sent":
        return sorted(devices, key=lambda d: d.get("last_sent") or "", reverse=True)
    if by == "version":
        return sorted(devices, key=lambda d: (d.get("ver") or "~", (d.get("name") or "~" + d["node"]).lower()))
    return sorted(devices, key=lambda d: (d.get("name") or "~" + d["node"]).lower())


STALE_DAYS = 7


def last_heard(device):
    """The latest proof the node is there: a result over the control plane, or the status
    Beacon last saw. ISO text or None."""
    seen = (device.get("fleet") or {}).get("seen")
    heard = device.get("last_heard")
    announced = (device.get("heard") or {}).get("at")      # an Observer node of yours caught its announce
    times = [x for x in (seen, heard, announced) if x]
    return max(times) if times else None


def _when(text):
    try:
        return datetime.datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return None


def battery(device):
    """The newest battery reading of a device, or None: `{mv, at, source, by}`. `source` is
    `beacon` (the node's own status, a node on Wi-Fi) or `heard` (the announce of a node without
    Wi-Fi, caught by `by`, one of your Observer nodes). With both, the newer."""
    fleet, heard = device.get("fleet") or {}, device.get("heard") or {}
    readings = []
    if fleet.get("battery_mv"):
        readings.append({"mv": fleet["battery_mv"], "at": fleet.get("seen"), "source": "beacon", "by": None})
    if heard.get("battery_mv"):
        readings.append({"mv": heard["battery_mv"], "at": heard.get("at"), "source": "heard",
                         "by": heard.get("by_name") or heard.get("by")})
    return max(readings, key=lambda r: _when(r["at"]) or datetime.datetime.min) if readings else None


def ago(when, now=None):
    age = relative(when, now)
    return age if age in ("-", "?", "now") else f"{age} ago"


def battery_text(device, now=None):
    """`3.71 V, 9 h ago, heard by Vindskydd`: the newest reading, its age and where it came
    from. Empty when there is none."""
    b = battery(device)
    if not b:
        return ""
    return f"{b['mv'] / 1000:.2f} V, {ago(b['at'], now)}, " + (f"heard by {b['by']}" if b["source"] == "heard"
                                                               else "from Beacon")


ANNOUNCE_SILENT_HOURS = 48     # a node that announces every 12 or 23 hours: silent after this


def announce_silent(device, now=None):
    """A node without Wi-Fi with no newer announce for about two days."""
    at = _when((device.get("heard") or {}).get("at"))
    now = now or datetime.datetime.now()
    return at is not None and (now - at).total_seconds() > ANNOUNCE_SILENT_HOURS * 3600


def heard_text(device, now=None):
    """`heard by Vindskydd 9 h ago, -5.5 dB, 2 hops` for a node without Wi-Fi that announced
    itself, else empty; `silent:` before it after about two days without a newer announce. The
    time is the command server's, when the Observer handed the announce in."""
    h = device.get("heard") or {}
    if not h:
        return ""
    hops = "direct" if not h.get("hops") else f"{h['hops']} hop{'s' if h['hops'] != 1 else ''}"
    snr = "" if h.get("snr") is None else f", {h['snr']:g} dB"
    return (f"{'silent: ' if announce_silent(device, now) else ''}heard by {h.get('by_name') or h.get('by')} "
            f"{ago(h.get('at'), now)}{' (read then)' if h.get('at_read') else ''}{snr}, {hops}")


def relays_text(device, devices=()):
    """The Observers that caught a node's announce, in the order a relay is chosen (`devices`
    are yours): `Vindskydd (yours, direct, 5 dB), 7316CA78 (2 hops, -4 dB, moved down: no answer
    twice)`. Empty when none."""
    from . import actions          # the ranking lives with the relay road
    parts = []
    for c in actions.rank_catchers(device, list(devices)):
        hops = actions.catcher_hops(c)
        said = ["yours"] if c["own"] else []
        said += ["direct" if not hops else f"{hops} hop{'s' if hops != 1 else ''}", f"{c['snr']:g} dB"]
        if c["demoted"]:
            said.append("moved down: no answer twice")
        parts.append(f"{c['name'] or c['node']} ({', '.join(said)})")
    return ", ".join(parts)


def stale(device, now=None, days=STALE_DAYS):
    """True when something was sent and nothing has been heard for `days`: a device to look
    at, not a verdict. A device never asked is not stale, it is unknown."""
    heard = last_heard(device)
    if not heard:
        return bool(device.get("last_sent"))
    try:
        then = datetime.datetime.fromisoformat(heard)
    except ValueError:
        return False
    now = now or datetime.datetime.now()
    return (now - then).total_seconds() > days * 86400


# The optional columns after name and node, in their order; `columns` in the configuration
# picks which show, so an 80-column terminal (38 columns for the directory) sees what the
# person asked for instead of the first that fit.
COLUMNS = ("reg", "sent", "batt", "seen", "ver", "result")


def row(device, width, now=None, columns=None):
    """One list row for a device, laid out to `width` columns.

    name (18)  node (8)  reg (4)  last sent (7)  batt (5)  seen (5)  ver (12)  result (rest)

    A name ending in ` ?` is a device something was sent to and nothing heard from for
    seven days, over the control plane or by Beacon: one to look at, not a verdict.
    `batt` and `seen` are what Beacon last said (`device["fleet"]`, filled by a refresh):
    battery in volts and the age of the node's last status. Blank until asked for. A node
    without Wi-Fi that announced itself (`device["heard"]`) shows what its announce said, the
    newer of the two.
    """
    name = (device.get("name") or "(unnamed)")
    name = (f"{name[:16]} ?" if stale(device, now) else name[:18]).ljust(18)
    node = device["node"][:8].ljust(8)
    shown = cells(device, now)
    if _narrow_ver(width, columns):                   # too narrow for the version: the revision alone
        shown["ver"] = revision(device.get("ver")).ljust(3)
    line = " ".join([name, node] + [shown[c] for c in chosen(columns)])
    return line[: width - 1].ljust(width - 1)


WIDTHS = {"reg": 4, "sent": 7, "batt": 5, "seen": 5, "ver": 12}


def _narrow_ver(width, columns):
    """True when the Ver column would be cut below `ar-10`: it is then the AR column, the
    revision number alone, which is what differs across a fleet. Wider, Ver is cut from the
    right, so the revision always shows."""
    picked = chosen(columns)
    if "ver" not in picked:
        return False
    before = 18 + 1 + 8 + sum(WIDTHS[c] + 1 for c in picked[:picked.index("ver")])
    return width - 1 - (before + 1) < 5


def revision(ver):
    """The auto-reply revision of a firmware string (`11` for `...-ar-11-...`), `-` for a
    build without one, empty when the version is unknown."""
    if not ver:
        return ""
    import re
    m = re.search(r"-ar-(\d+)", ver)
    return m.group(1) if m else "-"


def cells(device, now=None):
    """The optional columns of a row, each padded to its width, by name."""
    fleet = device.get("fleet") or {}
    newest = battery(device)
    heard_at = (device.get("heard") or {}).get("at")
    seen = max((x for x in (fleet.get("seen"), heard_at) if x), key=lambda x: _when(x) or datetime.datetime.min,
               default=None)
    return {
        "reg": (device.get("region") or "?")[:4].ljust(4),
        "sent": relative(device.get("last_sent"), now)[:7].ljust(7),
        "batt": (f"{newest['mv'] / 1000:.2f}" if newest else "")[:5].ljust(5),
        "seen": (relative(seen, now) if fleet or heard_at else "")[:5].ljust(5),
        "ver": version_short(device.get("ver"))[:12].ljust(12),
        "result": (device.get("last_result") or ""),
    }


def chosen(columns):
    """The configured columns in COLUMNS order; unknown names dropped; none means all."""
    wanted = {str(c).strip().lower() for c in (columns or ())}
    picked = [c for c in COLUMNS if c in wanted]
    return picked or list(COLUMNS)


def header(width, columns=None):
    heads = {"reg": f"{'Reg':4}", "sent": f"{'Sent':7}", "batt": f"{'Batt':5}", "seen": f"{'Seen':5}",
             "ver": "AR " if _narrow_ver(width, columns) else f"{'Ver':12}", "result": "Result"}
    return " ".join([f"{'Name':18}", f"{'Node':8}"] + [heads[c] for c in chosen(columns)])[: width - 1]


def version_short(ver):
    """`esp32s3-v1.17.1-ar-10-observer-42f48ce9` as `ar-10 1.17.1`: the auto-reply revision
    first, since it is what differs across a fleet and what survives a narrow column, then the
    version. A build without a revision is its version alone."""
    if not ver:
        return ""
    import re
    m = re.search(r"v?(\d+\.\d+(?:\.\d+)*)(?:-(ar-\d+))?", ver)
    if not m:
        return ver[:12]
    return f"{m.group(2)} {m.group(1)}" if m.group(2) else m.group(1)


def tag_footer(tagged, total):
    if not total:
        return "no devices"
    if tagged:
        return f"{tagged} of {total} tagged"
    return f"{total} device{'s' if total != 1 else ''}"
