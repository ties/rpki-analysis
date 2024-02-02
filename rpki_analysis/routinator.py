import io
from collections.abc import Buffer
from typing import Generator

import aiohttp
import pandas as pd


def read_csvext(buffer: Buffer) -> pd.DataFrame:
    """Read routinator csvext output into a dataframe"""
    return (
        pd.read_csv(buffer)
        .rename(
            columns={
                "URI": "uri",
                "ASN": "asn",
                "IP Prefix": "prefix",
                "Max Length": "max_length",
                "Not Before": "not_before",
                "Not After": "not_after",
            }
        )
        .astype({"max_length": int})
    )


async def read_csvext_url(url: str) -> pd.DataFrame:
    """Read routinator's csvext format"""
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            return read_csvext(io.BytesIO(await resp.read()))


async def read_jsonext_generator(url: str) -> Generator[object, None, None]:
    """Read routinator's jsonext format and flatten it"""
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            json = await resp.json()
            for row in json["roas"]:
                sources = row.pop("source")
                for source in sources:
                    validity = source.pop("validity")
                    chainvalidity = source.pop("chainValidity")

                    source["not_before"] = validity["notBefore"]
                    source["not_after"] = validity["notAfter"]

                    source["chain_not_before"] = chainvalidity["notBefore"]
                    source["chain_not_after"] = chainvalidity["notAfter"]
                    source.update(row)
                    yield source


async def read_jsonext(url: str) -> pd.DataFrame:
    """Read routinator's jsonext format"""
    df = pd.json_normalize([i async for i in read_jsonext_generator(url)])
    return df.rename(
        columns={
            "maxLength": "max_length",
        }
    ).astype({"max_length": int})
