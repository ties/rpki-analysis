import dataclasses
import lzma
from pathlib import Path

import pandas as pd
import pytest

from rpki_analysis.routinator import read_csvext
from rpki_analysis.rov import (
    RouteOriginAuthorization,
    RouteOriginAuthorizationLookup,
    rov_validity,
)


@dataclasses.dataclass
class AnnouncementStub:
    prefix: str
    origin: str


@pytest.fixture(scope="module")
def df_csvext() -> pd.DataFrame:
    """Fixture to get routinator csvext output."""
    with lzma.open(Path(__file__).parent / "data/routinator_csvext.csv.xz", "rt") as f:
        return read_csvext(f)


def test_roa_lookup(df_csvext: pd.DataFrame):  # pylint: disable=redefined-outer-name
    """roa lookup has two APIs - test both."""
    assert df_csvext.shape[0] > 100_000
    lookup = RouteOriginAuthorizationLookup(df_csvext)

    # Exact match
    as3333_vrps = set(
        [RouteOriginAuthorization(asn="AS3333", prefix="193.0.0.0/21", max_length=21)]
    )

    assert lookup["193.0.0.0/21"] == as3333_vrps
    assert list(lookup.lookup("193.0.0.0/21")) == list(as3333_vrps)
    # More specific -> also returns the covering VRP
    assert lookup["193.0.0.0/32"] == as3333_vrps
    assert list(lookup.lookup("193.0.0.0/32")) == list(as3333_vrps)

    # less specifics do not find their children
    assert lookup["193.0.0.0/16"] == set()
    assert not list(lookup.lookup("193.0.0.0/16"))

    # This prefix has three VRPs:
    assert lookup["100.20.0.0/14"] == set(
        [
            RouteOriginAuthorization("AS8987", "100.20.0.0/14", 24),
            RouteOriginAuthorization("AS14618", "100.20.0.0/14", 24),
            RouteOriginAuthorization("AS16509", "100.20.0.0/14", 24),
        ]
    )


def test_roa_validity(df_csvext: pd.DataFrame):  # pylint: disable=redefined-outer-name
    """Test rov_validity function"""
    assert df_csvext.shape[0] > 100_000
    lookup = RouteOriginAuthorizationLookup(df_csvext)

    assert rov_validity(AnnouncementStub("193.0.0.0/21", "AS3333"), lookup) == "valid"
    # different ASN
    assert rov_validity(AnnouncementStub("193.0.0.0/21", "AS3334"), lookup) == "invalid"
    # more specific not allowed
    assert rov_validity(AnnouncementStub("193.0.0.0/22", "AS3333"), lookup) == "invalid"
    # less specific is unknown
    assert rov_validity(AnnouncementStub("193.0.0.0/16", "AS3333"), lookup) == "unknown"

    # Now for the cases where there are multiple VRPs for the same prefix
    # 1: all three ASNs are valid
    assert rov_validity(AnnouncementStub("100.20.0.0/14", "AS8987"), lookup) == "valid"
    assert rov_validity(AnnouncementStub("100.20.0.0/14", "AS14618"), lookup) == "valid"
    assert rov_validity(AnnouncementStub("100.20.0.0/14", "AS16509"), lookup) == "valid"

    # 2: more specifics within max length are allowed
    assert rov_validity(AnnouncementStub("100.20.0.0/24", "AS16509"), lookup) == "valid"
    # But > is not
    assert (
        rov_validity(AnnouncementStub("100.20.0.0/25", "AS16509"), lookup) == "invalid"
    )
