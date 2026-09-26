import pytest

from emergency_envelope.common import Denied, decode_json, encode_json, fields
from emergency_envelope.crypto import Layer, join_key, new_data_key, open_envelope, seal, split_key

MSG = "B01호, 휠체어".encode()


def test_seal_and_open_round_trip():
    key = new_data_key()
    env = seal("HH-1", Layer.ENVELOPE_2, 1, MSG, key)
    assert b"B01" not in env.ciphertext
    assert open_envelope(env, key) == MSG


def test_swapping_envelope_to_another_household_fails():
    key = new_data_key()
    env = seal("HH-1", Layer.ENVELOPE_2, 1, MSG, key)
    for swapped in (env.relabel(household_id="HH-2"), env.relabel(layer=Layer.ENVELOPE_1), env.relabel(version=0)):
        with pytest.raises(Denied):
            open_envelope(swapped, key)


def test_any_two_shares_restore_key_but_one_does_not():
    key = new_data_key()
    s = split_key(key)
    assert len(s) == 3 and all(len(v) == 32 for v in s.values())
    for a, b in ((1, 2), (1, 3), (2, 3)):
        assert join_key({a: s[a], b: s[b]}) == key
    with pytest.raises(Denied):
        join_key({1: s[1]})


def test_encoding_is_unambiguous():
    assert fields("a,b", "c") != fields("a", "b,c")
    assert decode_json(encode_json({"구분자": "값"})) == {"구분자": "값"}
