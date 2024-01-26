import bz2
import io
import ipaddress
import itertools
from pathlib import Path

import netaddr
import pandas as pd
import pytest

from rpki_analysis.delegated_stats import (
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


def test_delegated_stats_parsing(df_delegated_stats: pd.DataFrame, caplog) -> None:
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

    uuid_by_rir = df[["rir", "uuid"]].drop_duplicates().groupby(["rir"]).count()
    # RIRs in order of size
    for (idx_lhs, rir_lhs), (idx_rhs, rir_rhs) in itertools.combinations(
        enumerate(["iana", "afrinic", "lacnic", "apnic", "arin", "ripencc"]), 2
    ):
        if idx_lhs < idx_rhs:
            assert uuid_by_rir.loc[rir_lhs].uuid < uuid_by_rir.loc[rir_rhs].uuid
        else:
            assert uuid_by_rir.loc[rir_lhs].uuid >= uuid_by_rir.loc[rir_rhs].uuid


def test_delegated_stats_lookup(df_delegated_stats: pd.DataFrame, caplog) -> None:
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


def test_delegated_stats_combiner(df_delegated_stats: pd.DataFrame, caplog) -> None:
    """This shares logic with the other lookup type, there is no need to cover as many cases"""
    caplog.set_level("DEBUG")

    lookup = StatsCombinedAllocations(df_delegated_stats)

    # a case covering multiple adjacent entries: this is merged in.
    prefix = ipaddress.ip_network("5.35.0.0/19")
    res = lookup[prefix]
    assert res.rir == "ripencc"
    # will be WAY more than 2 for this UUID
    # $ grep 466522a8-5734-42e3-b914-95b924dff466 nro-delegated-stats | wc -l
    # 237
    assert len(res.entries) >= 2
    # $ grepcidr 5.35.0.0/19 nro-delegated-stats
    # ripencc|RU|ipv4|5.35.0.0|4096|20120511|assigned|466522a8-5734-42e3-b914-95b924dff466|e-stats
    # ripencc|RU|ipv4|5.35.16.0|4096|20120511|assigned|466522a8-5734-42e3-b914-95b924dff466|e-stats
    assert len(res.overlapping_entries()) == 2
