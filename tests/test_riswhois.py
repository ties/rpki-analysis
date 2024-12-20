from pathlib import Path

import pandas as pd
import pytest

from rpki_analysis.riswhois import (
    ExpandedRisEntry,
    RisWhoisLookup,
    RisWhoisLookupMoreLessSpecific,
    RisWhoisLookupMoreSpecific,
    read_ris_dump,
)


@pytest.fixture(scope="module")
def df_v4() -> pd.DataFrame:
    with (Path(__file__).parent / "data/riswhoisdump.IPv4.gz").open("rb") as f:
        return read_ris_dump(f)


@pytest.mark.parametrize(
    "input_file", ["data/riswhoisdump.IPv4.gz", "data/riswhoisdump.IPv6.gz"]
)
def test_riswhois_parsing(input_file) -> None:
    with (Path(__file__).parent / input_file).open("rb") as f:
        df = read_ris_dump(f)

        assert "origin" in df.keys()
        assert "prefix" in df.keys()
        assert "prefix_length" in df.keys()


def test_riswhois_lookup(df_v4) -> None:
    lookup = RisWhoisLookup(df_v4)

    AS_3333_193_0_0_0_21 = ExpandedRisEntry(
        origin="3333", prefix="193.0.0.0/21", seen_by_peers=390, prefix_length=21
    )

    # lookup an IP
    assert AS_3333_193_0_0_0_21 in lookup["193.0.0.1"]
    # lookup a prefix (more specific)
    assert AS_3333_193_0_0_0_21 in lookup["193.0.0.0/24"]
    # lookup an exact match
    assert AS_3333_193_0_0_0_21 in lookup["193.0.0.0/21"]

    # when you look up a less specific, a more specific is not present
    assert AS_3333_193_0_0_0_21 not in lookup["193.0.0.0/16"]

    # When you look up a missing entry, you only get default routes.
    res = [(r.origin, r.prefix) for r in lookup["127.0.0.0/8"]]
    assert all(r[1] == "0.0.0.0/0" for r in res)


def test_riswhois_lookup_more_specific(df_v4) -> None:
    lookup = RisWhoisLookupMoreSpecific(df_v4)

    res = [(r.origin, r.prefix) for r in lookup["193.0.14.0/23"]]
    assert len(res) == 3
    assert ("25152", "193.0.14.0/23") in res
    assert ("25152", "193.0.14.0/24") in res
    assert ("25152", "193.0.15.0/24") in res

    # When you look up a missing entry, you get an empty result.
    # i.e. the more specifics of the first matching less specific (everything below 0/0) are not included.
    res = lookup["127.0.0.0/8"] == set()


def test_riswhois_lookup_more_less_specific(df_v4) -> None:
    lookup = RisWhoisLookupMoreLessSpecific(df_v4)

    res = [(r.origin, r.prefix) for r in lookup["193.0.14.0/23"]]
    assert len(res) == 4
    assert ("25152", "193.0.14.0/23") in res
    assert ("25152", "193.0.14.0/24") in res
    assert ("25152", "193.0.15.0/24") in res
    # and a default route (...)
    assert ("1299", "0.0.0.0/0") in res

    # look up less specifics
    AS_3333_193_0_0_0_21 = ExpandedRisEntry(
        origin="3333", prefix="193.0.0.0/21", seen_by_peers=390, prefix_length=21
    )

    # lookup an IP
    assert AS_3333_193_0_0_0_21 in lookup["193.0.0.1"]
    # lookup a prefix (more specific)
    assert AS_3333_193_0_0_0_21 in lookup["193.0.0.0/24"]
    # lookup an exact match
    assert AS_3333_193_0_0_0_21 in lookup["193.0.0.0/21"]

    # When you look up a missing entry, you only get default routes.
    res = [(r.origin, r.prefix) for r in lookup["127.0.0.0/8"]]
    assert all(r[1] == "0.0.0.0/0" for r in res)
