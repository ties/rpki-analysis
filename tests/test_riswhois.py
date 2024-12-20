from pathlib import Path

import pandas as pd
import pytest

from rpki_analysis.riswhois import ExpandedRisEntry, RisWhoisLookup, read_ris_dump


@pytest.mark.parametrize(
    "input_file", ["data/riswhoisdump.IPv4.gz", "data/riswhoisdump.IPv6.gz"]
)
def test_riswhois_parsing(input_file) -> None:
    with (Path(__file__).parent / input_file).open("rb") as f:
        df = read_ris_dump(f)

        assert "origin" in df.keys()
        assert "prefix" in df.keys()
        assert "prefix_length" in df.keys()


def test_riswhois_lookup() -> None:
    df_v4 = read_ris_dump(Path(__file__).parent / "data/riswhoisdump.IPv4.gz")
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
