import bz2
import io
import itertools
from pathlib import Path
from typing import TextIO

import pytest

from rpki_analysis.delegated_stats import read_delegated_stats


@pytest.fixture
def delegated_stats_fd() -> TextIO:
    """Fixture to get delegated stats file descriptor"""
    with bz2.open(Path(__file__).parent / "data/nro-delegated-stats.bz2", "rt") as f:
        return io.StringIO(f.read())


def test_delegated_stats_parsing(delegated_stats_fd: TextIO, caplog) -> None:
    caplog.set_level("DEBUG")
    df = read_delegated_stats(delegated_stats_fd)
    assert df.dtypes["rir"] == "category"

    data = df.groupby(["rir"]).count()
    assert data.loc["ripencc"].country > 100000

    uuid_by_rir = df[["rir", "uuid"]].drop_duplicates().groupby(["rir"]).count()
    # RIRs in order of size
    for (idx_lhs, rir_lhs), (idx_rhs, rir_rhs) in itertools.combinations(
        enumerate(["iana", "afrinic", "lacnic", "apnic", "arin", "ripencc"]), 2
    ):
        if idx_lhs < idx_rhs:
            assert uuid_by_rir.loc[rir_lhs].uuid < uuid_by_rir.loc[rir_rhs].uuid
        else:
            assert uuid_by_rir.loc[rir_lhs].uuid >= uuid_by_rir.loc[rir_rhs].uuid
