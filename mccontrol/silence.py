"""Why a command over the mesh got no answer, and what to try: the wording, as pure functions.

Silence over the mesh is one of two things the tool usually cannot tell apart: the node was out
of answer airtime (it then says nothing, and counts the request under `refused` in `get cmd`),
or a packet was lost. It can tell when a `get cmd` read before the silence and one after it show
`refused` rising. Nothing here sends anything: only what was already read is used.

Per device the store keeps `{"direct": n, "base": m, "refused": m}`: direct sends in a row
without an answer; the `refused` count of a `get cmd` read with no mesh send after it; and that
count carried across a silence, to compare with the next read. A node counts a request it
answered with a refusal under `refused` too, so such an answer drops the count carried.
"""

import re

MESH_ROADS = ("mesh", "relay")
READS = ("get cmd", "get mqtt.cmd")         # lou-20, and the name on lou-19
FLOOD_AFTER = 2

UNKNOWN = ("it may be out of answer airtime (wait a few minutes; get cmd counts it under refused), "
           "or the packet was lost on the way")
REFUSED = ("refused rose from {before} to {after} across the silence: the node refused for lack of "
           "answer airtime; wait a few minutes and send again")
FLOOD = {"relay": "{n} direct sends in a row without an answer: the path may be stale; a flooded send "
                  "renews it (--route flood)",
         "mesh": "{n} direct sends in a row without an answer: the path may be stale; a flooded send "
                 "through a relay renews the way (--via relay:DEVICE --route flood)"}
PATH_NOTE = ("note: --path {hex} is read as {n} one-byte hops; three-byte hashes are written "
             "--path 3:{hex}")


def refused_count(command, reply):
    """The `refused` count in a `get cmd` reply (", mesh <mode> ok <n> refused <m>"), or None."""
    if " ".join((command or "").split()).lower() not in READS:
        return None
    m = re.search(r"\bmesh \S+ ok \d+ refused (\d+)", reply or "")
    return int(m.group(1)) if m else None


def step(state, road, outcome, direct=False, read=None):
    """`(state, before, after)` after one send. `outcome` is ok, refused (the node answered
    with a refusal), silent (sent, no answer) or unknown (not known whether it was sent);
    `direct` says a mesh-road send followed a stored path; `read` is the `refused` count
    when this answer was a `get cmd`. `before` and `after` are the two counts around a
    silence, each None unless both are known."""
    s = {"direct": 0, "base": None, "refused": None, **(state or {})}
    before = after = None
    if road in MESH_ROADS:
        if outcome == "silent":
            if s["refused"] is None:
                s["refused"] = s["base"]
            s["direct"] = s["direct"] + 1 if direct else 0
        else:
            if outcome != "unknown":
                s["direct"] = 0
            if outcome != "ok":
                s["refused"] = None
        s["base"] = None
    if read is not None:
        if s["refused"] is not None:
            before, after = s["refused"], read
        s["refused"], s["base"] = None, read
    return s, before, after


def advice(road, outcome, losses=0, before=None, after=None):
    """The lines to show under a result: what a silence over the mesh can mean and what to
    do; that the node refused for lack of airtime, when the two counts say so; and, after
    two direct sends in a row without an answer, a flooded send. A suggestion only."""
    lines = []
    if before is not None and after is not None and after > before:
        lines.append(REFUSED.format(before=before, after=after))
    if road in MESH_ROADS and outcome == "silent":
        lines.append(UNKNOWN)
        if losses >= FLOOD_AFTER:
            lines.append(FLOOD[road].format(n=losses))
    return lines


def path_note(text):
    """A note for a `--path` given as plain hex whose length is whole three-byte hashes: it
    is read as one-byte hops. None for any other path; the path is sent as given."""
    text = (text or "").strip()
    if len(text) % 6 or not re.fullmatch(r"[0-9A-Fa-f]+", text):
        return None
    return PATH_NOTE.format(hex=text.upper(), n=len(text) // 2)
