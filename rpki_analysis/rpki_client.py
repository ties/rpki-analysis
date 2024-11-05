import io
import itertools
import json
from typing import Generator

import aiohttp
import pandas as pd


async def read_dump_url(url: str) -> pd.DataFrame:
    """Read rpki-client dump format"""
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            return read_dump(io.StringIO(await resp.text()))


def read_dump_generator(row: object) -> Generator[object, None, None]:
    """
    Create a flat version of:
    ```json
    {
        "file": "repo-rpki.idnic.net/repo/17e65b67-905c-403c-8c79-2315659668aa/0/3138302e3231342e3234362e302f32342d3234203d3e203338313530.roa",
        "hash_id": "pSMqZyq3tofIqbVs5e+fl67udIcuxiGW/jxUt5sa3SU=",
        "type": "roa",
        "ski": "1E:58:4B:38:B6:8A:A1:B2:F9:03:E5:66:94:01:5E:97:95:9E:E8:D9",
        "cert_issuer": "/CN=2CA47487F72781733330A38C95FF8A5DF68CDBB9",
        "cert_serial": "3EB5BD76D054FC5C17D515DB35955E105EDF1A8E",
        "aki": "2C:A4:74:87:F7:27:81:73:33:30:A3:8C:95:FF:8A:5D:F6:8C:DB:B9",
        "aia": "rsync://repo-rpki.idnic.net/repo/IDNIC-ID/2/2CA47487F72781733330A38C95FF8A5DF68CDBB9.cer",
        "sia": "rsync://repo-rpki.idnic.net/repo/17e65b67-905c-403c-8c79-2315659668aa/0/3138302e3231342e3234362e302f32342d3234203d3e203338313530.roa",
        "signing_time": 1719795810,
        "valid_since": 1719795510,
        "valid_until": 1751245410,
        "expires": 1720266202,
        "vrps": [
            {
            "prefix": "180.214.246.0/24",
            "asid": 38150,
            "maxlen": 24
            }
        ],
        "validation": "OK"
    }
    ```
    """
    vrps = row.pop("vrps", [])
    for vrp in vrps:
        vrp.update(row)
        yield vrp


def read_dump(dump: io.StringIO) -> pd.DataFrame:
    """Read rpki-client dump format"""
    lines = dump.read().splitlines()

    df = pd.DataFrame(
        itertools.chain.from_iterable(map(read_dump_generator, map(json.loads, lines)))
    )
    return df.rename(columns={"maxlen": "max_length", "asid": "asn"}).astype(
        {"asn": int, "max_length": int}
    )
