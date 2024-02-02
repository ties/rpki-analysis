import bz2
import io
import ipaddress
import itertools
from pathlib import Path

import netaddr
import pandas as pd
import pytest

from rpki_analysis.delegated_stats import (
    RirLookup,
    StatsCombinedAllocations,
    StatsEntryLookup,
    read_delegated_stats,
)


@pytest.fixture(scope="module")
def df_delegated_stats() -> pd.DataFrame:
    """Fixture to get delegated stats file descriptor"""
    with bz2.open(Path(__file__).parent / "data/nro-delegated-stats.bz2", "rt") as f:
        data = io.StringIO(f.read())

        return read_delegated_stats(data)


def test_delegated_stats_parsing(
    df_delegated_stats: pd.DataFrame, caplog
) -> None:  # pylint: disable=redefined-outer-name
    df = df_delegated_stats
    caplog.set_level("DEBUG")
    assert df.dtypes["rir"] == "category"

    data = df.groupby(["rir"]).count()
    assert data.loc["ripencc"].country > 100000

    # check the first line is present
    assert df.loc[0].rir == "iana"
    assert df.loc[0].afi == "asn"
    assert df.loc[0].resource == "0"
    # assert the length is correct
    assert df.loc[0].length == 1

    opaque_id_rir = df[["rir", "opaque_id"]].drop_duplicates().groupby(["rir"]).count()
    # RIRs in order of size
    for (idx_lhs, rir_lhs), (idx_rhs, rir_rhs) in itertools.combinations(
        enumerate(["iana", "afrinic", "lacnic", "apnic", "arin", "ripencc"]), 2
    ):
        if idx_lhs < idx_rhs:
            assert (
                opaque_id_rir.loc[rir_lhs].opaque_id
                < opaque_id_rir.loc[rir_rhs].opaque_id
            )
        else:
            assert (
                opaque_id_rir.loc[rir_lhs].opaque_id
                >= opaque_id_rir.loc[rir_rhs].opaque_id
            )


def test_delegated_stats_lookup(
    df_delegated_stats: pd.DataFrame, caplog
) -> None:  # pylint: disable=redefined-outer-name
    caplog.set_level("DEBUG")

    lookup = StatsEntryLookup(df_delegated_stats)

    # check that the boundaries apply correctly
    assert lookup["193.0.0.0/32"].rir == "ripencc"
    assert lookup["193.0.0.0/20"].rir == "ripencc"
    assert lookup["193.0.15.255/32"].rir == "ripencc"

    # a case covering multiple adjacent entries: Not in delegated stats
    with pytest.raises(KeyError):
        assert lookup["5.35.0.0/19"].rir == "ripencc"

    # a case where the entry is not in the set
    assert lookup["193.0.11.51/32"].rir == "ripencc"
    assert lookup["2001:67c:2e8:25::c100:b34/128"].rir == "ripencc"

    # case where it is in the tree
    assert lookup["199.5.26.0/24"].rir == "arin"
    assert lookup["2001:500:A9::/48"].rir == "arin"

    # too large
    with pytest.raises(KeyError):
        lookup.__getitem__("0.0.0.0/0")

    # lookup netaddr types
    assert lookup[netaddr.IPNetwork("199.5.26.0/24")].rir == "arin"
    assert lookup[netaddr.IPNetwork("2001:500:A9::/48")].rir == "arin"

    # lookup the children on the type that does not merge entries
    network = netaddr.IPNetwork("145.0.0.0/8")
    count = 0
    for element in lookup.children(network):
        count += 1
        assert element.resource in network

    assert count > 64


def test_delegated_stats_combiner(
    df_delegated_stats: pd.DataFrame, caplog
) -> None:  # pylint: disable=redefined-outer-name
    """This shares logic with the other lookup type, there is no need to cover as many cases"""
    caplog.set_level("DEBUG")

    lookup = StatsCombinedAllocations(df_delegated_stats)

    # a case covering multiple adjacent entries: this is merged in.
    prefix = ipaddress.ip_network("5.35.0.0/19")
    res = lookup[prefix]
    assert res.rir == "ripencc"
    # will be WAY more than 2 for this opaque id
    # $ grep 466522a8-5734-42e3-b914-95b924dff466 nro-delegated-stats | wc -l
    # 237
    assert len(res.entries) >= 2
    # $ grepcidr 5.35.0.0/19 nro-delegated-stats
    # ripencc|RU|ipv4|5.35.0.0|4096|20120511|assigned|466522a8-5734-42e3-b914-95b924dff466|e-stats
    # ripencc|RU|ipv4|5.35.16.0|4096|20120511|assigned|466522a8-5734-42e3-b914-95b924dff466|e-stats
    assert len(res.overlapping_entries()) == 2


def test_rir_lookup(
    df_delegated_stats: pd.DataFrame, caplog
) -> None:  # pylint: disable=redefined-outer-name
    """This shares logic with the other lookup type, there is no need to cover as many cases"""
    caplog.set_level("DEBUG")

    lookup = RirLookup(df_delegated_stats)
    assert lookup["145.0.0.0/9"] == "ripencc"
    assert lookup["103.73.236.0/24"] == "apnic"
    assert lookup["103.73.237.0/24"] == "apnic"
    assert lookup["103.73.238.0/24"] == "apnic"
    # Get returns the same
    assert lookup.get("145.0.0.0/9") == "ripencc"

    # Use get on an entry that is missing
    assert lookup.get("0.0.0.0/0") is None
    # And get returns defaults
    assert lookup.get("0.0.0.0/0", "default") == "default"

    # A prefix with differing more-specifics is also not found
    assert lookup.get("130.0.0.0/8") is None
