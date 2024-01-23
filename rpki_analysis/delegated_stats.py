import logging
from typing import TextIO

import netaddr
import pandas as pd

LOG = logging.getLogger(__name__)


def extract_resource(row) -> netaddr.IPNetwork | str:
    match (row.afi):
        case "ipv4":
            start = netaddr.IPAddress(row.prefix)
            return netaddr.IPRange(start, start + (row.prefix_size - 1))
        case "ipv6":
            return f"{row.prefix}/{row.prefix_size}"
        case "asn":
            return row.prefix
        case _:
            raise ValueError()


def read_delegated_stats(f: TextIO) -> pd.DataFrame:
    df_delegated_extended = pd.read_csv(
        f,
        sep="|",
        skiprows=8,
        names=[
            "rir",
            "country",
            "afi",
            "prefix",
            "prefix_size",
            "date",
            "status",
            "uuid",
            "category",
        ],
        dtype={
            "rir": "category",
            "country": "category",
            "afi": "category",
            "prefix": str,
            "size": int,
            "date": str,
            "status": "category",
            "uuid": str,
            "category": "category",
        },
    )

    # Fix unsupported dates
    df_delegated_extended.loc[
        df_delegated_extended.date == "00000000", "date"
    ] = "19700101"

    df_delegated_extended.date = pd.to_datetime(
        df_delegated_extended.date, format="%Y%m%d", utc=True
    )
    df_delegated_extended["resource"] = df_delegated_extended.apply(
        extract_resource, axis=1
    )
    return df_delegated_extended
