import ipaddress
import logging
from abc import abstractmethod
from typing import Generator, NamedTuple, Set

import netaddr
import pandas as pd
import pytricia
from pandas.core.series import Series

from rpki_analysis.datastructures import BasePytriciaLookup, PrefixType

LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)


class ExpandedRisEntry(NamedTuple):
    """Because this can contain AS sets (e.g. {12703}), origins are strings."""

    origin: str
    prefix: str
    seen_by_peers: int
    prefix_length: int


def read_ris_dump(url: str) -> pd.DataFrame:
    # Get file, accept that there are comment lines in there
    df = pd.read_csv(
        url, compression="gzip", sep="\t", names=["origin", "prefix", "seen_by_peers"]
    )

    if df.origin.str.startswith("{").any():
        LOG.warning(
            "RIS dump contains row(s) with AS_SET! These will never be RPKI valid (https://tools.ietf.org/html/rfc6907#section-7.1.8)"
        )
    # select the rows that do not have the '%' prefix
    df = df[~df.origin.str.startswith("%")].copy()

    # separate prefix length
    df["prefix_length"] = df.prefix.map(lambda p: ipaddress.ip_network(p).prefixlen)

    return df


class RisWhoisLookupTrie(BasePytriciaLookup[Set[ExpandedRisEntry]]):
    def __init__(self, data: pd.DataFrame, visibility_threshold: int = 10) -> None:
        super().__init__(initial_value=set)

        assert set(data.keys()) >= set(
            [
                "origin",
                "prefix",
                "seen_by_peers",
                "prefix_length",
            ]
        )
        data[(data.seen_by_peers >= visibility_threshold)].apply(
            self.__build_trie, axis=1
        )

    def __build_trie(self, row: pd.Series) -> None:
        # pytricia: has_key searches for exact match, in for prefix match
        # we want exact match.

        trie = self._trie(row.prefix)

        if not trie.has_key(row.prefix):  # noqa: W601
            # Add entry
            trie[row.prefix] = set()

        trie[row.prefix].add(
            ExpandedRisEntry(
                row.origin,
                row.prefix,
                row.seen_by_peers,
                row.prefix_length,
            )
        )

    @abstractmethod
    def lookup(self, prefix: PrefixType) -> Generator[ExpandedRisEntry, None, None]:
        pass

    def __contains__(self, prefix) -> bool:
        return prefix in self._trie(prefix)

    def __getitem__(self, prefix) -> Set[ExpandedRisEntry]:
        return set(self.lookup(prefix))


class RisWhoisLookup(RisWhoisLookupTrie):
    def lookup(self, prefix) -> Generator[ExpandedRisEntry, None, None]:
        trie = self._trie(prefix)
        key = trie.get_key(prefix)
        while key is not None:
            yield from trie[key]
            key = trie.parent(key)


class RisWhoisLookupMoreSpecific(RisWhoisLookupTrie):
    """Lookup more or equally specific elements."""

    def lookup(self, prefix) -> Generator[ExpandedRisEntry, None, None]:
        resource = netaddr.IPSet(netaddr.IPNetwork(prefix))
        trie = self._trie(prefix)

        keys = [trie.get_key(str(prefix))]
        while keys:
            key = keys.pop()
            # Do not include children of elements that are not in the resource
            # (it would be a less specific).
            if not resource.issuperset(netaddr.IPSet(netaddr.IPNetwork(key))):
                continue

            child_keys = list(trie.children(key))
            keys.extend(child_keys)

            # do not yield None elements
            elem = trie[key]
            if elem is not None:
                yield from elem


class RisWhoisLookupMoreLessSpecific(RisWhoisLookupTrie):
    """Lookup more or equally specific elements."""

    def lookup(self, prefix) -> Generator[ExpandedRisEntry, None, None]:
        resource = netaddr.IPSet(netaddr.IPNetwork(prefix))
        trie = self._trie(prefix)

        keys = [trie.get_key(str(prefix))]
        # Gather the more specifics
        while keys:
            key = keys.pop()
            # Do not include children of elements that are not in the resource
            # (it would be a less specific).
            if not resource.issuperset(netaddr.IPSet(netaddr.IPNetwork(key))):
                continue

            child_keys = list(trie.children(key))
            keys.extend(child_keys)

            # do not yield None elements
            elem = trie[key]
            if elem is not None:
                yield from elem

        # exact match + less specific
        key = trie.get_key(str(prefix))
        while key is not None:
            yield from trie[key]
            key = trie.parent(key)
