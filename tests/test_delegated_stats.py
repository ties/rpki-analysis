import io
import bz2
import pytest

from typing import TextIO

from pathlib import Path

from rpki_analysis.delegated_stats import read_file



@pytest.fixture
def delegated_stats_fd() -> TextIO:
    """Fixture to get delegated stats file descriptor"""
    with bz2.open(Path("data/nro-delegated-stats.bz2", "rt")) as f:
        return f
    

def test_delegated_stats_parsing(delegated_stats_fd: TextIO) -> None:
    df = read_file(delegated_stats_fd)
    assert df.dtypes["rir"] == "category"

