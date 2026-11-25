"""Why a mesh command got no answer, and what to try: the wording as a pure function of the
road, the outcome, the direct sends lost in a row, the two `refused` counts and the path text."""
import pytest

from mccontrol import silence


def test_the_refused_count_is_read_from_get_cmd_only():
    reply = "> on, counter 1795000000, mesh on ok 4 refused 2"
    assert silence.refused_count("get cmd", reply) == 2
    assert silence.refused_count("get  mqtt.cmd", "> on, mesh auto ok 0 refused 11") == 11
    assert silence.refused_count("get cmd", "> on, counter 5, mesh only, mesh on ok 0 refused 0") == 0
    assert silence.refused_count("get relay", "> own, forwarded 3, answered 2, refused 1") is None
    assert silence.refused_count("get cmd", "> off") is None
    assert silence.refused_count("get name", reply) is None


@pytest.mark.parametrize("road", ["mesh", "relay"])
def test_silence_over_the_mesh_says_both_causes_and_claims_neither(road):
    assert silence.advice(road, "silent") == [silence.UNKNOWN]
    assert "may be out of answer airtime" in silence.UNKNOWN and "or the packet was lost" in silence.UNKNOWN
    assert "get cmd" in silence.UNKNOWN and "wait a few minutes" in silence.UNKNOWN


@pytest.mark.parametrize("outcome", ["ok", "refused", "unknown"])
def test_only_silence_over_the_mesh_gets_the_advice(outcome):
    assert silence.advice("mesh", outcome, losses=5) == []
    assert silence.advice("mqtt", "silent", losses=5) == []


def test_a_refused_count_that_rose_across_the_silence_is_said_and_nothing_else_is():
    assert silence.advice("mqtt", "ok", before=2, after=3) == [silence.REFUSED.format(before=2, after=3)]
    assert "lack of answer airtime" in silence.REFUSED
    for before, after in ((3, 3), (3, 0), (None, 3), (3, None)):      # the same, a restart, one read only
        assert silence.advice("mqtt", "ok", before=before, after=after) == []


def test_two_direct_losses_in_a_row_suggest_a_flood_by_its_option():
    assert silence.advice("relay", "silent", losses=1) == [silence.UNKNOWN]
    two = silence.advice("relay", "silent", losses=2)
    assert two == [silence.UNKNOWN, silence.FLOOD["relay"].format(n=2)] and "--route flood" in two[1]
    mesh = silence.advice("mesh", "silent", losses=3)[1]
    assert mesh.startswith("3 direct sends") and "--via relay:DEVICE --route flood" in mesh


def test_the_count_is_of_direct_sends_in_a_row_and_any_answer_ends_it():
    s, _b, _a = silence.step(None, "relay", "silent", direct=True)
    s, _b, _a = silence.step(s, "mesh", "silent", direct=True)
    assert s["direct"] == 2
    assert silence.step(s, "relay", "silent", direct=False)[0]["direct"] == 0     # a flood is not a direct loss
    assert silence.step(s, "relay", "ok", direct=True)[0]["direct"] == 0
    assert silence.step(s, "mesh", "refused", direct=True)[0]["direct"] == 0
    assert silence.step(s, "relay", "unknown", direct=True)[0]["direct"] == 2     # not known to have been sent
    assert silence.step(s, "mqtt", "ok")[0]["direct"] == 2                         # MQTT says nothing of the path


def test_the_two_counts_are_the_reads_before_and_after_the_silence():
    s, before, after = silence.step(None, "mqtt", "ok", read=2)
    assert (before, after) == (None, None)
    s, before, after = silence.step(s, "mesh", "silent", direct=True)
    assert (before, after) == (None, None) and s["refused"] == 2
    s, _b, _a = silence.step(s, "mesh", "silent", direct=True)                    # a second silence keeps the first count
    s, before, after = silence.step(s, "mqtt", "ok", read=4)
    assert (before, after) == (2, 4) and s["refused"] is None and s["base"] == 4
    assert silence.step(s, "mqtt", "ok", read=5)[1:] == (None, None)              # no silence between: nothing to say


def test_a_read_over_the_mesh_after_the_silence_counts_too():
    s, _b, _a = silence.step(None, "relay", "ok", read=1)
    s, _b, _a = silence.step(s, "relay", "silent")
    assert silence.step(s, "relay", "ok", read=2)[1:] == (1, 2)


def test_a_count_that_other_sends_could_have_raised_is_not_used():
    read, _b, _a = silence.step(None, "mqtt", "ok", read=2)
    # a mesh send between the read and the silence: an answered refusal is counted too
    s, _b, _a = silence.step(read, "mesh", "refused")
    s, _b, _a = silence.step(s, "mesh", "silent")
    assert silence.step(s, "mqtt", "ok", read=4)[1:] == (None, None)
    # an answered refusal, or a send of unknown fate, after the silence
    for outcome in ("refused", "unknown"):
        s, _b, _a = silence.step(read, "mesh", "silent")
        s, _b, _a = silence.step(s, "relay", outcome)
        assert silence.step(s, "mqtt", "ok", read=4)[1:] == (None, None), outcome
    # no read before the silence at all
    s, _b, _a = silence.step(None, "mesh", "silent")
    assert silence.step(s, "mqtt", "ok", read=4)[1:] == (None, None)


def test_plain_hex_of_whole_three_byte_hashes_gets_a_note():
    note = silence.path_note("a1b2c3D4E5F6")
    assert note == ("note: --path A1B2C3D4E5F6 is read as 6 one-byte hops; three-byte hashes are written "
                    "--path 3:A1B2C3D4E5F6")
    assert silence.path_note(" A1B2C3 ") is not None
    for quiet in ("A1B2", "A1B2C3D4", "3:A1B2C3", "1:A1B2C3", "2:A1B2C3D4E5F6", "none", "", None, "A1B2CX"):
        assert silence.path_note(quiet) is None, quiet
