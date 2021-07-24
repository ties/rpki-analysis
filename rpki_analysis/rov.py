import logging
from typing import Generator, NamedTuple, Optional, Set

import altair as alt
import pandas as pd
import pytricia
import requests
from pandas.core.series import Series

LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)


class RouteOriginAuthorization(NamedTuple):
    """A ROA"""

    asn: int
    prefix: str
    max_length: int

    prefix_length: Optional[int] = None


class RouteOriginAuthorizationLookup:
    """
    Build patricia tries for storing ROAs.

    The entries of the patricia tries will be a set of RouteOriginAuthorization that are an
    exact match for the prefix of a key.

    To lookup all applicable ROAs for a value, first retrieve the most specific entry,
    followed by looking up the parents.
    """

    trie: pytricia.PyTricia

    def __init__(self, data: pd.DataFrame) -> None:
        assert data.af.nunique() == 1
        length = 128 if data.af.unique()[0] == 6 else 32

        self.trie = pytricia.PyTricia(length)
        data.apply(self.__build_trie, axis=1)

    def __build_trie(self, row: Series) -> None:
        if row.prefix not in self.trie:
            # Add entry
            self.trie[row.prefix] = set()

        self.trie[row.prefix].add(
            RouteOriginAuthorization(
                row.asn, row.prefix, row.maxLength, row.prefix_length
            )
        )

    def __getitem__(self, prefix) -> Set[RouteOriginAuthorization]:
        return set(self.lookup(prefix))

    def lookup(self, prefix) -> Generator[RouteOriginAuthorization, None, None]:
        key = self.trie.get_key(prefix)
        while key is not None:
            yield from self.trie[key]
            key = self.trie.parent(key)


def rov_validity(ris_entry: Series, lookup: RouteOriginAuthorizationLookup) -> str:
    """
    Determine ROA validation outcome for an entry.

    Algorithm from `RFC6483 section 2 <https://tools.ietf.org/html/rfc6483#section-2>`_.
    """
    # A route validity state is defined by the following procedure:
    #
    # 1. Select all valid ROAs that include a ROAIPAddress value that
    #    either matches, or is a covering aggregate of, the address
    #    prefix in the route.  This selection forms the set of
    #    "candidate ROAs".
    roa = None
    # Lookup only returns objects that have a identical or less specific prefix.
    for roa in lookup.lookup(ris_entry.prefix):
        # 3. If the route's origin AS can be determined and any of the set
        #    of candidate ROAs has an asID value that matches the origin AS
        #    in the route, and
        if roa.asn == ris_entry.origin:
            # the route's address prefix matches a
            #    ROAIPAddress in the ROA (where "match" is defined as where the
            #    route's address precisely matches the ROAIPAddress, or where
            #    the ROAIPAddress includes a maxLength element, and the route's
            #    address prefix is a more specific prefix of the ROAIPAddress,
            #    and the route's address prefix length value is less than or
            #    equal to the ROAIPAddress maxLength value), then the procedure
            #    halts with an outcome of "valid".
            if roa.max_length and roa.max_length >= ris_entry.prefix_length:
                return "valid"
    if roa:
        # 4. Otherwise, the procedure halts with an outcome of "invalid".
        return "invalid"
    else:
        # 2. If the set of candidate ROAs is empty, then the procedure stops
        #    with an outcome of "unknown" (or, synonymously, "not found", as
        #    used in [BGP-PFX]).
        return "unknown"


def rov_validity_verbose(
    ris_entry: Series, lookup: RouteOriginAuthorizationLookup
) -> str:
    """Verbose version of roa_validity function."""
    # Match roas, to match, they need to:
    # * have the same AS as the ROA
    # * have a prefix length <= maxLength
    roas = lookup[ris_entry.prefix]
    if not roas:
        return "unknown"
    was_valid = False
    for roa in roas:
        print(roa)
        if roa.asn != ris_entry.origin:
            LOG.info(
                "invalid as: %s ris origin: %d for %s",
                roa,
                ris_entry.origin,
                ris_entry.prefix,
            )
        else:
            assert roa.prefix_length <= ris_entry.prefix_length
            if roa.max_length >= ris_entry.prefix_length:
                LOG.info(
                    "valid roa: %s for %s announced by %s",
                    roa,
                    ris_entry.prefix,
                    ris_entry.origin,
                )
                was_valid = True
            else:
                LOG.info("invalid length: %s does not match %s", ris_entry.prefix)

    return "valid" if was_valid else "invalid"
