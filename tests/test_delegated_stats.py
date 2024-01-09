import bz2
import io
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
