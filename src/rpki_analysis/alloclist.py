import datetime
import io
from typing import TextIO

import aiohttp
import polars as pl

ALLOCLIST_URL = "https://ftp.ripe.net/pub/stats/ripencc/membership/alloclist.txt"


def _parse_record(lines: list[str], i: int) -> tuple[dict, int]:
    """Parse a single alloclist record starting at line i.

    Returns the parsed record and the index after the last consumed line.
    """
    reg_id = lines[i].strip()
    i += 1

    name = lines[i].strip() if i < len(lines) else ""
    i += 1

    # Skip blank line(s) between name and resources
    while i < len(lines) and not lines[i].strip():
        i += 1

    # Resource lines are indented and tab-separated; run until blank line or EOF
    resources: list[dict] = []
    while i < len(lines) and lines[i].strip() and lines[i][0].isspace():
        parts = lines[i].strip().split("\t")
        date_str = parts[0]
        resources.append(
            {
                "date": datetime.date(
                    int(date_str[:4]), int(date_str[4:6]), int(date_str[6:8])
                ),
                "resource": parts[1],
                "state": parts[2] if len(parts) > 2 else None,
            }
        )
        i += 1

    return {"reg_id": reg_id, "name": name, "resources": resources}, i


def read_alloclist(f: TextIO) -> pl.DataFrame:
    """Parse a RIPE NCC alloclist into a dataframe."""
    lines = f.read().splitlines()
    records: list[dict] = []
    i = 0

    while i < len(lines):
        if not lines[i].strip():
            i += 1
        elif not lines[i][0].isspace():
            record, i = _parse_record(lines, i)
            records.append(record)
        else:
            i += 1

    return pl.DataFrame(
        records,
        schema={
            "reg_id": pl.Utf8,
            "name": pl.Utf8,
            "resources": pl.List(
                pl.Struct({"date": pl.Date, "resource": pl.Utf8, "state": pl.Utf8})
            ),
        },
    )


async def read_alloclist_url(url: str = ALLOCLIST_URL) -> pl.DataFrame:
    """Fetch and parse a RIPE NCC alloclist."""
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            return read_alloclist(io.StringIO(await resp.text()))
