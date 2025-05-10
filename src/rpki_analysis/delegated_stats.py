import datetime
import ipaddress
import logging
from dataclasses import dataclass
from typing import Generator, List, TextIO, TypeVar

import netaddr
import pandas as pd
import pytricia
import polars as pl

LOG = logging.getLogger(__name__)

PrefixType = str | netaddr.IPNetwork | ipaddress.IPv4Network | ipaddress.IPv6Network

V = TypeVar("V")


@dataclass
class DelegatedExtendedStatsEntry:
    rir: str
    country: str
    afi: str
    length: int
    date: datetime.date
    status: str
    """
    For APNIC:
      * NIR subaccounts have IDs that begin with A92
      * all other accounts have IDs that begin with A91
    """
    opaque_id: str
    category: str
    resource: netaddr.IPNetwork | str


@dataclass
class CombinedEntry:
    rir: str
    opaque_id: str
    entries: List[DelegatedExtendedStatsEntry]
    resource: netaddr.IPRange

    def overlapping_entries(self) -> List[DelegatedExtendedStatsEntry]:
        return [entry for entry in self.entries if entry.resource in self.resource]


def extract_resource(row) -> netaddr.IPNetwork | str:
    """Transform a row into an IP resource"""
    match (row.afi):
        case "ipv4":
            start = netaddr.IPAddress(row.raw_resource)
            return netaddr.IPRange(start, start + (row.length - 1))
        case "ipv6":
            return netaddr.IPNetwork(f"{row.raw_resource}/{row.length}")
        case "asn":
            if row.length == 1:
                return row.raw_resource
            else:
                return f"{row.raw_resource}-{int(row.raw_resource) + row.length}"
        case _:
            raise ValueError()

def normalized_delegated_extended_stats(f: TextIO) -> pl.DataFrame:
    """Parse a delegated stats file into a dataframe"""
    df_delegated_extended = pl.read_csv(
        f,
        separator="|",
        skip_rows=4,
        has_header=False,
        new_columns=[
            "rir",
            "country",
            "afi",
            "raw_resource",
            "length",
            "date",
            "status",
            "opaque_id",
            "category",
        ],
        schema_overrides={
            "rir": pl.Categorical,
            "country": pl.Categorical,
            "afi": pl.Categorical,
            "raw_resource": pl.Utf8,
            "length": pl.Int64,
            "date": pl.Utf8,
            "status": pl.Categorical,
            "opaque_id": pl.Utf8,
            "category": pl.Categorical,
        },
    )

    # Fix unsupported dates
    df_delegated_extended = df_delegated_extended.with_columns(
        pl.when(pl.col("date") == "00000000")
        .then(datetime.date(1970, 1, 1))
        .otherwise(pl.col("date"))
        .alias("date")
    )

    df_delegated_extended = df_delegated_extended.with_columns(
        pl.col("date").str.strptime(pl.Date, "%Y%m%d", strict=False)
    )
    import ipdb; ipdb.set_trace()
    # Create processed_resources column with the results from our function
    df_with_resources = df_delegated_extended.with_columns(
        pl.struct(["raw_resource", "length", "afi"])
        .map_elements(lambda row: process_ip_resources(
            row["raw_resource"], 
            row["length"], 
            row["afi"]
        ), return_dtype=pl.List(pl.Utf8))
        .alias("resources")
    )
    import ipdb; ipdb.set_trace()
    
    # Explode the dataframe to create one row per resource
    return df_with_resources.explode("resources")

def read_delegated_extended_stats(f: TextIO) -> pd.DataFrame:
    """Parse a delegated stats file into a dataframe"""
    df_delegated_extended = pd.read_csv(
        f,
        sep="|",
        skiprows=4,
        names=[
            "rir",
            "country",
            "afi",
            "raw_resource",
            "length",
            "date",
            "status",
            "opaque_id",
            "category",
        ],
        dtype={
            "rir": "category",
            "country": "category",
            "afi": "category",
            "raw_resource": str,
            "length": int,
            "date": str,
            "status": "category",
            "opaque_id": str,
            "category": "category",
        },
    )

    # Fix unsupported dates
    df_delegated_extended.loc[df_delegated_extended.date == "00000000", "date"] = (
        "19700101"
    )

    df_delegated_extended.date = pd.to_datetime(
        df_delegated_extended.date, format="%Y%m%d", utc=True
    )
    df_delegated_extended["resource"] = df_delegated_extended.apply(
        extract_resource, axis=1
    )
    return df_delegated_extended


def read_delegated_stats(f: TextIO) -> pd.DataFrame:
    """Parse a delegated stats file into a dataframe"""
    df_delegated = pd.read_csv(
        f,
        sep="|",
        skiprows=4,
        names=[
            "rir",
            "country",
            "afi",
            "raw_resource",
            "length",
            "date",
            "status",
        ],
        dtype={
            "rir": "category",
            "country": "category",
            "afi": "category",
            "raw_resource": str,
            "length": int,
            "date": str,
            "status": "category",
        },
    )

    # Fix unsupported dates
    df_delegated.loc[df_delegated.date == "00000000", "date"] = "19700101"

    df_delegated.date = pd.to_datetime(df_delegated.date, format="%Y%m%d", utc=True)
    df_delegated["resource"] = df_delegated.apply(extract_resource, axis=1)
    return df_delegated


def process_ip_resources(raw_resource: str, length: int, afi: str) -> List[str]:
    """
    Process raw_resource and length to return a list of IP resources.
    
    Args:
        raw_resource: The raw resource value (e.g. IP address or ASN)
        length: The length value
        afi: Address family ("ipv4", "ipv6", or "asn")
        
    Returns:
        List of processed IP resources in string format
    """
    match afi:
        case "ipv4":
            start = netaddr.IPAddress(raw_resource)
            ip_range = netaddr.IPRange(start, start + (length - 1))
            # Return a list of CIDR blocks that make up this range
            return list(map(str, ip_range.cidrs()))
        case "ipv6":
            return [f"{raw_resource}/{length}"]
        case "asn":
            # For ASNs, just return as a single-element list
            return [raw_resource]
        case _:
            raise ValueError(f"Unsupported address family: {afi}")


class PytriciaLookup[V]:
    """
    Base type for lookup implementations.

    `__init__` should build the two tries by afi.
    """

    trie4: pytricia.PyTricia
    trie6: pytricia.PyTricia

    def __init__(self) -> None:
        self.trie4 = pytricia.PyTricia(32)
        self.trie6 = pytricia.PyTricia(128)

        # include 'root' element so children works
        self.trie4["0.0.0.0/0"] = None
        self.trie6["::/0"] = None

    def __contains__(self, prefix: str) -> bool:
        return prefix in self.trie4 or prefix in self.trie6

    def __trie(self, prefix: PrefixType) -> pytricia.PyTricia:
        """Get the relevant of trie."""
        match type(prefix):
            case netaddr.IPNetwork:
                return self.trie6 if prefix.version == 6 else self.trie4
            case ipaddress.IPv4Network:
                return self.trie4
            case ipaddress.IPv6Network:
                return self.trie6
            case _:
                return self.trie4 if "." in prefix else self.trie6

    def get(self, prefix: PrefixType, default=None) -> V:
        """Get the value and default to None"""
        lookup = self.__trie(prefix)

        res = lookup[str(prefix)]
        if res is None:
            return default
        return res

    def __getitem__(self, prefix: PrefixType) -> V:
        res = self.__trie(prefix)[str(prefix)]

        if res is None:
            raise KeyError(prefix)

        return res

    def children(self, prefix: PrefixType) -> Generator[V, None, None]:
        """Recursively get all children of a prefix"""
        lookup = self.__trie(prefix)
        resource = ipaddress.ip_network(prefix)

        keys = [lookup.get_key(str(prefix))]
        while keys:
            key = keys.pop()
            # do not include super-nets of the resource being looked up
            child_keys = [
                k
                for k in lookup.children(key)
                if ipaddress.ip_network(k).overlaps(resource)
            ]
            keys.extend(child_keys)

            # do not yield None elements
            elem = lookup[key]
            if elem is not None:
                yield elem


class StatsEntryLookup(PytriciaLookup[DelegatedExtendedStatsEntry]):
    """
    Lookup the RIR for a given resource.
    """

    def __init__(self, data: pd.DataFrame) -> None:
        super().__init__()
        assert set(data.keys()) >= set(
            [
                "rir",
                "country",
                "afi",
                "length",
                "date",
                "status",
                "opaque_id",
                "category",
                "resource",
            ]
        )
        data[data.afi != "asn"].apply(self.__build_trie, axis=1)

    def __build_trie(self, row: pd.Series) -> None:
        # pytricia: has_key searches for exact match, in for prefix match
        # we want exact match.

        record = DelegatedExtendedStatsEntry(
            rir=row.rir,
            country=row.country,
            afi=row.afi,
            length=row.length,
            date=row.date,
            status=row.status,
            opaque_id=row.opaque_id,
            category=row.category,
            resource=row.resource,
        )

        match row.afi:
            case "ipv4":
                for cidr in row.resource.cidrs():
                    self.trie4[str(cidr)] = record
            case "ipv6":
                self.trie6[str(row.resource)] = record
            case _:
                raise ValueError()


class StatsCombinedAllocations(PytriciaLookup[CombinedEntry]):
    """
    Lookup the combined allocation and delegated stats lines for a given resource.
    """

    def __init__(self, data: pd.DataFrame) -> None:
        super().__init__()
        assert set(data.keys()) >= set(
            [
                "rir",
                "country",
                "afi",
                "length",
                "date",
                "status",
                "opaque_id",
                "category",
                "resource",
            ]
        )
        data[data.afi != "asn"].groupby(["opaque_id", "afi", "rir"]).apply(
            self.__build_trie
        )

    def __build_trie(self, rows: pd.Series) -> None:
        """Build trie entries for the groups of rows.

        @precondition grouped by opaque_id, afi, rir.
        """
        opaque_ids = rows.opaque_id.unique()
        assert len(opaque_ids) == 1
        opaque_id = opaque_ids[0]

        afis = rows.afi.unique()
        assert len(afis) == 1
        afi = afis[0]

        rirs = rows.rir.unique()
        assert len(rirs) == 1
        rir = rirs[0]

        records = [
            DelegatedExtendedStatsEntry(
                rir=row.rir,
                country=row.country,
                afi=row.afi,
                length=row.length,
                date=row.date,
                status=row.status,
                opaque_id=row.opaque_id,
                category=row.category,
                resource=row.resource,
            )
            for _, row in rows.iterrows()
        ]

        resources = netaddr.IPSet([entry.resource for entry in records])
        for cidr in resources.iter_cidrs():
            combined = CombinedEntry(
                rir=rir, opaque_id=opaque_id, entries=records, resource=cidr
            )
            if afi == "ipv4":
                self.trie4[str(cidr)] = combined
            elif afi == "ipv6":
                self.trie6[str(cidr)] = combined
            else:
                raise ValueError()


class RirLookup(PytriciaLookup[str]):
    """
    Just find the RIR responsible for the range
    """

    def __init__(self, data: pd.DataFrame) -> None:
        super().__init__()
        assert set(data.keys()) >= set(
            [
                "rir",
                "country",
                "afi",
                "length",
                "date",
                "status",
                "opaque_id",
                "category",
                "resource",
            ]
        )
        data[data.afi != "asn"].groupby(["afi", "rir"]).apply(self.__build_trie)

    def __build_trie(self, rows: pd.Series) -> None:
        """Build trie entries for the groups of rows.
        @precondition grouped by opaque_id, afi, rir.
        """
        afis = rows.afi.unique()
        assert len(afis) == 1
        afi = afis[0]

        rirs = rows.rir.unique()
        assert len(rirs) == 1
        rir = rirs[0]

        cidrs = netaddr.cidr_merge([row.resource for (_, row) in rows.iterrows()])
        for cidr in cidrs:
            if afi == "ipv4":
                self.trie4[str(cidr)] = rir
            elif afi == "ipv6":
                self.trie6[str(cidr)] = rir
            else:
                raise ValueError()
