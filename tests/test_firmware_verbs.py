"""Every command the table offers must be one the firmware's console takes (W-22).

The verbs are read from the firmware's own source: each `memcmp`/`strcmp` of the command
line (or of the part after `set `/`get `) that is not inside another one's block is a verb,
and the literals compared inside a `set` verb's block are the values it takes. A table entry
passes when every line it can build is matched by a verb, and a `choice` of a `set` is one of
that verb's values (a numeric choice where the block reads a number, `off` where the block
only tests for `on`). A verb whose block says it "is gone" is retired and matches nothing.

The firmware tree is the Observer fork's worktree next to this repository, or
MCCONTROL_FIRMWARE; without one the comparison is skipped and the parser is still tested on
a small sample below.
"""
import os
import pathlib
import re

import pytest

from mccontrol import commands

FIRMWARE = pathlib.Path(os.environ.get("MCCONTROL_FIRMWARE")
                        or pathlib.Path(__file__).resolve().parents[2] / "Meshcore-observer-autoreply" / "wt-observer")
SOURCES = ("src/helpers/CommonCLI.cpp", "src/helpers/CommonCLI_Observer.cpp", "src/helpers/CommonRadioPrefs.cpp",
           "src/helpers/AutoReplyLogic.h", "examples/simple_repeater/*.cpp")

_CMP = re.compile(r'\b(memcmp|strcmp|strncmp|strncasecmp|strcasecmp)\(\s*(&?\w+(?:\[[^\]]*\])?(?:\s*\+\s*\d+)?)\s*,\s*"([^"]*)"')
_PREFIX = re.compile(r'static const char PREFIX\[\] = "([^"]*)"')
_FUNC = re.compile(r'^[A-Za-z_][\w:<>*& ]*?\b(\w+)\s*\([^;]*$', re.M)
_NUMBER = re.compile(r'\b(_?atoi|atof|strtol|strtoul)\(')


def _blank(text):
    """Comments, string and character contents as spaces, so braces count and positions stay."""
    out, i, n = list(text), 0, len(text)

    def blank(a, b):
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        two = text[i:i + 2]
        if two == "//":
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif two == "/*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            blank(i, j)
            i = j
        elif text[i] in "\"'":
            q, j = text[i], i + 1
            while j < n and text[j] != q:
                j += 2 if text[j] == "\\" else 1
            blank(i + 1, j)                  # the quotes stay, what is between goes
            i = j + 1
        else:
            i += 1
    return "".join(out)


def _block(masked, pos):
    """(start, end) of the `{...}` block that follows `pos`, or (pos, pos) if a `;` comes first."""
    open_at = masked.find("{", pos)
    semi = masked.find(";", pos)
    if open_at < 0 or (0 <= semi < open_at):
        return pos, pos
    depth = 0
    for k in range(open_at, len(masked)):
        if masked[k] == "{":
            depth += 1
        elif masked[k] == "}":
            depth -= 1
            if depth == 0:
                return open_at, k
    return open_at, len(masked)


def _prefix_for(var, func):
    if var == "config":
        return "set " if func.endswith("SetCmd") else "get " if func.endswith("GetCmd") else None
    if var == "subcmd":
        return "set mqtt1." if func.endswith("SetCmd") else "get mqtt1." if func.endswith("GetCmd") else None
    if var == "parts[1]":
        return "region "
    if var in ("command", "cmd"):
        return ""
    return None


def verbs(text):
    """[(verb, exact, values, numeric)] from one source file's text."""
    masked = _blank(text)
    funcs = [(m.start(), m.group(1)) for m in _FUNC.finditer(masked)]
    found = []
    for m in _CMP.finditer(text):
        if masked[m.start()] == " ":          # inside a comment
            continue
        func = next((f for p, f in reversed(funcs) if p <= m.start()), "")
        prefix = _prefix_for(m.group(2).strip(), func)
        if prefix is None:
            continue
        start, end = _block(masked, m.end())
        exact = m.group(1) in ("strcmp", "strcasecmp") and prefix != "region "   # `region put <args>`
        found.append([prefix + m.group(3), exact, start, end, m.start()])
    for m in _PREFIX.finditer(text):
        found.append([m.group(1), False, m.end(), m.end(), m.start()])
    out = []
    for verb, exact, start, end, at in found:
        if any(s < at < e for _, _, s, e, a in found if a != at and s != e):
            continue                         # a value inside another verb's block
        body = text[start:end]
        if "is gone" in body:
            continue                         # retired: answers an error
        values = {v for _, _, v in _CMP.findall(body)}
        out.append((verb, exact, values, bool(_NUMBER.search(body))))
    return out


def firmware_verbs(root):
    out = []
    for pattern in SOURCES:
        for path in sorted(root.glob(pattern)):
            out += verbs(path.read_text(errors="replace"))
    return out


def _samples(c):
    if c.kind in ("choice", "multi"):
        return [(commands.build(c, [v]), v) for v in c.choices]
    if c.kind == "text":
        ex = [e for e in c.examples if "<" not in e] or ["x"]
        if c.text in ("get", "set"):
            return [(e, None) for e in ex if e.startswith(c.text + " ")] or [(c.text + " txdelay 0.5", None)]
        return [(commands.build(c, [e]), None) for e in ex]
    return [(c.text, None)]


GENERIC = ("get ", "set ", "region", "")   # dispatchers: they match a line only as themselves
_SLOT = re.compile(r"\bmqtt[1-6]\.")


def problems(table, found):
    """The table's lines the firmware does not take, as readable sentences."""
    bad = []
    for c in table:
        for line, value in _samples(c):
            line = _SLOT.sub("mqtt1.", line)  # the firmware reads the slot's digit, 1 to MAX_MQTT_SLOTS (6)
            hits = [v for v in found if line == v[0].rstrip()
                    or (not v[1] and v[0] not in GENERIC and line.startswith(v[0]))]
            if not hits:
                bad.append(f"{c.text!r}: the firmware has no verb for {line!r}")
                continue
            if value is None or not value or not line.startswith("set "):
                continue
            verb = max(hits, key=lambda v: len(v[0]))
            if line.rstrip() == verb[0].rstrip():
                continue
            if verb[2]:
                ok = value in verb[2] or (value == "off" and "on" in verb[2])
            elif verb[3]:
                ok = value.lstrip("-").replace(".", "", 1).isdigit()
            else:
                ok = True
            if not ok:
                bad.append(f"{c.text!r}: {value!r} is not a value {verb[0].strip()!r} takes"
                           f" ({', '.join(sorted(verb[2])) or 'a number'})")
    return bad


SAMPLE = r'''
void CommonCLI::handleCommand(uint32_t ts, char* command, char* reply) {
  if (memcmp(command, "ver", 3) == 0) {          // "get nothing" in a comment
    strcpy(reply, "1");
  } else if (memcmp(command, "set ", 4) == 0) {
    handleSetCmd(ts, command, reply);
  }
}
void CommonCLI::handleSetCmd(uint32_t ts, char* command, char* reply) {
  const char* config = &command[4];
  if (memcmp(config, "loop.detect ", 12) == 0) {
    config += 12;
    if (memcmp(config, "off", 3) == 0) { mode = 0; } else if (memcmp(config, "strict", 6) == 0) { mode = 3; }
  } else if (memcmp(config, "cad ", 4) == 0) {
    set(memcmp(&config[4], "on", 2) == 0);
  }
}
bool Prefs::handle(const char* command, char* reply) {
  if (memcmp(command, "set multi.acks ", 15) == 0) {
    setMultiAcks(atoi(&command[15]));
    return true;
  }
  if (memcmp(command, "set old.delay", 13) == 0) {
    strcpy(reply, "Err - old.delay is gone; use new");
    return true;
  }
  return false;
}
'''


def _entry(text, kind="none", choices=(), examples=()):
    return commands.Command(text, "tuning", kind, tuple(choices), tuple(examples), False)


def test_the_parser_reads_verbs_values_and_retired_ones():
    found = verbs(SAMPLE)
    names = {v[0] for v in found}
    assert {"ver", "set ", "set loop.detect ", "set cad ", "set multi.acks "} <= names
    assert "set off" not in names and "set old.delay" not in names and "get nothing" not in names
    good = [_entry("ver"), _entry("set loop.detect", "choice", ("off", "strict")),
            _entry("set cad", "choice", ("on", "off")), _entry("set multi.acks", "choice", ("0", "1"))]
    assert problems(good, found) == []
    bad = [_entry("set loop.detect", "choice", ("0", "3")), _entry("set multi.acks", "choice", ("on", "off")),
           _entry("set old.delay", "text", examples=("60",)), _entry("set nothing", "text", examples=("1",))]
    assert len(problems(bad, found)) == 6


@pytest.mark.skipif(not (FIRMWARE / "src/helpers/CommonCLI.cpp").exists(), reason="no firmware tree at hand")
def test_every_table_entry_is_a_firmware_verb():
    found = firmware_verbs(FIRMWARE)
    assert len(found) > 100
    assert problems(commands.TABLE, found) == []
