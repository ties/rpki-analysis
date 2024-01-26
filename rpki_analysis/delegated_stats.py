import datetime
import ipaddress
import logging
from dataclasses import dataclass
from typing import Generator, List, TextIO, TypeVar

import netaddr
import pandas as pd
import pytricia

LOG = logging.getLogger(__name__)

PrefixType = str | netaddr.IPNetwork | ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass
class DelegatedStatsEntry:
    rir: str
    country: str
    afi: str
    length: int
    date: datetime.date
    status: str
    uuid: str
    category: str
    resource: netaddr.IPNetwork | str


@dataclass
class CombinedEntry:
    rir: str
    entries: List[DelegatedStatsEntry]
    resource: netaddr.IPRange

    def overlapping_entries(self) -> List[DelegatedStatsEntry]:
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
            return row.raw_resource
        case _:
            raise ValueError()


def read_delegated_stats(f: TextIO) -> pd.DataFrame:
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
            "uuid",
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


V = TypeVar("V")


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

    def get(self, prefix: PrefixType) -> V:
        lookup = self.__trie(prefix)

        res = lookup[str(prefix)]
        if res is None:
            raise KeyError(prefix)

        return res

    def __getitem__(self, prefix: PrefixType) -> V:
        return self.get(prefix)

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


class StatsEntryLookup(PytriciaLookup[DelegatedStatsEntry]):
    """
    Lookup the RIR for a given resource.
    """

    def __init__(self, data: pd.DataFrame) -> None:
        super().__init__()
        data[data.afi != "asn"].apply(self.__build_trie, axis=1)

    def __build_trie(self, row: pd.Series) -> None:
        # pytricia: has_key searches for exact match, in for prefix match
        # we want exact match.

        record = DelegatedStatsEntry(
            rir=row.rir,
            country=row.country,
            afi=row.afi,
            length=row.length,
            date=row.date,
            status=row.status,
            uuid=row.uuid,
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
        data[data.afi != "asn"].groupby(["uuid", "afi"]).apply(self.__build_trie)

    def __build_trie(self, rows: pd.Series) -> None:
        # pytricia: has_key searches for exact match, in for prefix match
        # we want exact match.

        records = [
            DelegatedStatsEntry(
                rir=row.rir,
                country=row.country,
                afi=row.afi,
                length=row.length,
                date=row.date,
                status=row.status,
                uuid=row.uuid,
                category=row.category,
                resource=row.resource,
            )
            for _, row in rows.iterrows()
        ]

        afis = rows.afi.unique()
        assert len(afis) == 1
        afi = afis[0]

        rirs = rows.rir.unique()
        assert len(rirs) == 1
        rir = rirs[0]

        resources = netaddr.IPSet([entry.resource for entry in records])
        for cidr in resources.iter_cidrs():
            combined = CombinedEntry(rir=rir, entries=records, resource=cidr)
            if afi == "ipv4":
                self.trie4[str(cidr)] = combined
            elif afi == "ipv6":
                self.trie6[str(cidr)] = combined
            else:
                raise ValueError()
