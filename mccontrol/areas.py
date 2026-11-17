"""The areas an owner picks from (W-20b): Sweden's counties, each with its scope and the IATA
code(s) its observers use on MQTT. The control plane is addressed by IATA; owners know their
county and their scope (`se-jkp`), so the web app shows the county and the scope and sends to
the IATA codes underneath.

Copied from the regional site template (github.com/sweden-mesh/meshcore-regional-template),
which is where the sites read them:

- county name and scope: `assets/meshcore-se-regioner/regioner.csv` (columns scb_lan, lan,
  region), the template's copy of zombiefredrik/meshcore-se-regioner;
- IATA: `hugo.toml`, `[params.observer.iatas]` (SCB code -> IATA, as Beacon lists them).

`tests/test_areas.py` compares this table with a template checkout beside this repository
(or at `$MCCONTROL_TEMPLATE`) and fails when they differ; `python -m mccontrol.webexport`
writes it to `web/lib/data/areas.json`.
"""

import csv
import io
import re

SOURCE = "meshcore-regional-template v0.47.0 (2026-11-17): regioner.csv and hugo.toml [params.observer.iatas]"

# (SCB code, county, scope, IATA codes), in SCB order.
AREAS = (
    ("01", "Stockholms län", "se-sth", ("STO",)),
    ("03", "Uppsala län", "se-upp", ("STO",)),
    ("04", "Södermanlands län", "se-sor", ("NYO",)),
    ("05", "Östergötlands län", "se05", ("LPI",)),
    ("06", "Jönköpings län", "se-jkp", ("JKG",)),
    ("07", "Kronobergs län", "se-kro", ("VXO",)),
    ("08", "Kalmar län", "se08", ("KLR",)),
    ("09", "Gotlands län", "se-gtl", ("VBY",)),
    ("10", "Blekinge län", "se-blk", ("RNB",)),
    ("12", "Skåne län", "se12", ("MMX",)),
    ("13", "Hallands län", "se13", ("HAD",)),
    ("14", "Västra Götalands län", "se-vgr", ("GOT",)),
    ("17", "Värmlands län", "se17", ("KSD",)),
    ("18", "Örebro län", "se18", ("ORB",)),
    ("19", "Västmanlands län", "se-vml", ("VST",)),
    ("20", "Dalarnas län", "se20", ("BLE",)),
    ("21", "Gävleborgs län", "se-gav", ("GVX",)),
    ("22", "Västernorrlands län", "se-vnl", ("SDL",)),
    ("23", "Jämtlands län", "se23", ("OSD",)),
    ("24", "Västerbottens län", "se-vbt", ("UME",)),
    ("25", "Norrbottens län", "se-nbt", ("LLA",)),
)


def iatas_of(scb):
    """The IATA codes of the county with SCB code `scb`, or () when there is none."""
    return next((a[3] for a in AREAS if a[0] == scb), ())


def from_template(regioner_csv, hugo_toml):
    """The same table built from the template's two files' text, for the staleness test."""
    rows = list(csv.DictReader(io.StringIO(regioner_csv)))
    block = re.search(r"^\[params\.observer\.iatas\]\s*$(.*?)(?=^\[|\Z)", hugo_toml, re.M | re.S)
    if not block:
        raise ValueError("hugo.toml has no [params.observer.iatas] table")
    iata = dict(re.findall(r'^\s*"(\d\d)"\s*=\s*"([A-Z0-9]{2,8})"', block.group(1), re.M))
    return tuple((r["scb_lan"], r["lan"], r["region"], (iata[r["scb_lan"]],) if r["scb_lan"] in iata else ())
                 for r in rows)
