"""The area table (W-20b) is the regional template's: county and scope from its regioner.csv,
the IATA from its hugo.toml. Compared with a template checkout when one is at hand."""
import os
import pathlib

import pytest

from mccontrol import areas

TEMPLATE = pathlib.Path(os.environ.get("MCCONTROL_TEMPLATE")
                        or pathlib.Path(__file__).resolve().parents[2] / "meshcore-regional-template")


def test_every_county_has_a_scope_and_an_iata():
    assert len(areas.AREAS) == 21
    assert len({a[0] for a in areas.AREAS}) == 21
    for scb, county, scope, iatas in areas.AREAS:
        assert county.endswith(" län") and scope.startswith("se") and iatas
    assert areas.iatas_of("06") == ("JKG",) and areas.iatas_of("99") == ()


def test_from_template_reads_both_files():
    csv_text = "scb_lan,lan,region,beslut\n06,Jönköpings län,se-jkp,lokalt\n02,Nowhere län,se02,x\n"
    toml = '[params.observer]\n  preset = "x"\n[params.observer.iatas]\n  "06" = "JKG"\n  "01" = "STO"\n[params.other]\n  "02" = "NOP"\n'
    assert areas.from_template(csv_text, toml) == (("06", "Jönköpings län", "se-jkp", ("JKG",)),
                                                   ("02", "Nowhere län", "se02", ()))


@pytest.mark.skipif(not (TEMPLATE / "hugo.toml").is_file(), reason="no regional template checkout beside this repository")
def test_table_matches_the_template():
    got = areas.from_template((TEMPLATE / "assets/meshcore-se-regioner/regioner.csv").read_text(encoding="utf-8"),
                              (TEMPLATE / "hugo.toml").read_text(encoding="utf-8"))
    assert got == areas.AREAS, "the template's counties, scopes or IATA codes changed: update mccontrol/areas.py"
