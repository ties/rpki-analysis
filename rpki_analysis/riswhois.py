import ipaddress
import logging
from typing import Generator, NamedTuple, Set

import pandas as pd
import pytricia
from pandas.core.series import Series

LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)


class ExpandedRisEntry(NamedTuple):
    origin: str
    prefix: str
    seen_by_peers: int
    prefix_length: int
    roa_validity: str


def read_ris_dump(url: str) -> pd.DataFrame:
    # Get file, accept that there are comment lines in there
    df = pd.read_csv(
        url, compression="gzip", sep="\t", names=["origin", "prefix", "seen_by_peers"]
    )

    if df.origin.str.startswith("{").any():
        LOG.error(
            "RIS dump contains row(s) with AS_SET! These will never be RPKI valid (https://tools.ietf.org/html/rfc6907#section-7.1.8)"
        )
    # select the rows that do not have the '%' prefix
    df = df[~df.origin.str.startswith("%")].copy()

    # separate prefix length
    df["prefix_length"] = df.prefix.map(lambda p: ipaddress.ip_network(p).prefixlen)

    return df


class RisWhoisLookup:
    trie: pytricia.PyTricia

    def __init__(self, data: pd.DataFrame, visibility_threshold: int = 10) -> None:
        af = data.prefix.apply(lambda p: ipaddress.ip_network(p).version)
        assert af.nunique() == 1
        length = 128 if af.unique()[0] == 6 else 32

        self.trie = pytricia.PyTricia(length)
        data[data.seen_by_peers >= visibility_threshold].apply(
            self.__build_trie, axis=1
        )

    def __build_trie(self, row: Series) -> None:
        if not row.prefix not in self.trie:
            # Add entry
            self.trie[row.prefix] = set()

        self.trie[row.prefix].add(
            ExpandedRisEntry(
                row.origin,
                row.prefix,
                row.seen_by_peers,
                row.prefix_length,
                row.roa_validity,
            )
        )

    def lookup(self, prefix) -> Generator[ExpandedRisEntry, None, None]:
        key = self.trie.get_key(prefix)
        while key is not None:
            yield from self.trie[key]
            key = self.trie.parent(key)

    def __getitem__(self, prefix) -> Set[ExpandedRisEntry]:
        return set(self.lookup(prefix))
