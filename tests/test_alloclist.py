import datetime
from pathlib import Path

import polars as pl
import pytest

from rpki_analysis.alloclist import read_alloclist


@pytest.fixture(scope="module")
def df_alloclist() -> pl.DataFrame:
    with (Path(__file__).parent / "data/alloclist-minimal.txt").open() as f:
        return read_alloclist(f)


def test_alloclist_schema(df_alloclist: pl.DataFrame) -> None:
    assert df_alloclist.schema == {
        "reg_id": pl.Utf8,
        "name": pl.Utf8,
        "resources": pl.List(
            pl.Struct({"date": pl.Date, "resource": pl.Utf8, "state": pl.Utf8})
        ),
    }


def test_alloclist_reg_ids(df_alloclist: pl.DataFrame) -> None:
    assert df_alloclist["reg_id"].to_list() == [
        "ad.andorpac",
        "empty.test",
        "ripe.test",
    ]


def test_alloclist_names(df_alloclist: pl.DataFrame) -> None:
    assert df_alloclist["name"].to_list() == [
        "ANDORRA TELECOM, S.A.U.",
        "EMPTY MEMBER",
        "RIPE NCC TEST MEMBER",
    ]


def test_alloclist_resources(df_alloclist: pl.DataFrame) -> None:
    resources = df_alloclist["resources"].to_list()

    # First entry: 2 IPv4 with state, 1 IPv6 without state
    assert len(resources[0]) == 3
    assert resources[0][0] == {
        "date": datetime.date(1996, 6, 27),
        "resource": "194.158.64.0/19",
        "state": "ALLOCATED PA",
    }
    assert resources[0][1] == {
        "date": datetime.date(1999, 9, 16),
        "resource": "213.236.8.0/21",
        "state": "ALLOCATED PA",
    }
    # state is None when the line has only date and resource
    assert resources[0][2] == {
        "date": datetime.date(2011, 7, 22),
        "resource": "2a02:8060::/31",
        "state": None,
    }

    # Second entry: member with no resources
    assert resources[1] == []

    # Third entry: one with state, one without
    assert len(resources[2]) == 2
    assert resources[2][0] == {
        "date": datetime.date(2020, 1, 1),
        "resource": "193.0.0.0/21",
        "state": "ALLOCATED PA",
    }
    assert resources[2][1] == {
        "date": datetime.date(2021, 6, 15),
        "resource": "2001:67c::/32",
        "state": None,
    }
