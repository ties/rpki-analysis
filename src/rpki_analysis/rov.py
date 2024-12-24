import ipaddress
import logging
from typing import Generator, Literal, NamedTuple, Optional, Protocol, Set, Union

import netaddr
import pandas as pd
import pytricia

LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)


PrefixType = Union[str, ipaddress.IPv4Network, ipaddress.IPv6Network, netaddr.IPNetwork]


class ValidatedRoaPayload(Protocol):
    """The shape of a VRP."""

    asn: str
    prefix: str
    max_length: Optional[int] = None


class Announcement(Protocol):
    """The shape of a BGP announcement (or RIS entry)."""

    """The origin, without 'AS' prefix, but potentially as a AS set."""
    prefix: str
    origin: str
    prefix_length: int


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

    trie4: pytricia.PyTricia
    trie6: pytricia.PyTricia

    def __init__(self, data: pd.DataFrame) -> None:
        # expected columns
        assert set(data.keys()) >= set(["asn", "prefix", "max_length"])
        # We use asn as a int to avoid the "AS" prefix
        assert data.asn.dtype == int

        self.trie4 = pytricia.PyTricia(32)
        self.trie6 = pytricia.PyTricia(128)

        data.apply(self.__build_trie, axis=1)

    def __trie(self, prefix: str) -> pytricia.PyTricia:
        return self.trie4 if ":" not in prefix else self.trie6

    def __build_trie(self, row: ValidatedRoaPayload) -> None:
        # pytricia: has_key searches for exact match, in for prefix match
        # we want exact match.
        assert isinstance(row.prefix, str)
        trie = self.__trie(row.prefix)

        if not trie.has_key(row.prefix):  # noqa: W601
            # Add entry
            trie[row.prefix] = set()

        trie[row.prefix].add(
            RouteOriginAuthorization(
                row.asn, row.prefix, row.max_length, getattr(row, "prefix_length", None)
            )
        )

    def __contains__(self, prefix: PrefixType) -> bool:
        return prefix in self.__trie(str(prefix))

    def __getitem__(self, prefix: PrefixType) -> Set[RouteOriginAuthorization]:
        return set(self.lookup(str(prefix)))

    def lookup(
        self, prefix: PrefixType
    ) -> Generator[RouteOriginAuthorization, None, None]:
        """Lookup VRPs for prefix and all less specifics."""
        # look up the key in the trie matching the prefix
        # (the match is a direct match or less specific)
        prefix = str(prefix)
        trie = self.__trie(prefix)

        key = trie.get_key(prefix)
        while key is not None:
            # yield **all** VRPs for the prefix match
            yield from trie[key]
            # and possibly continue with the next less specific prefix match
            key = trie.parent(key)


def rov_validity(
    announcement: Announcement, lookup: RouteOriginAuthorizationLookup
) -> Literal["valid", "invalid", "unknown"]:
    """
    Determine ROA validation outcome for an entry.

    Algorithm from `RFC6483 section 2 <https://tools.ietf.org/html/rfc6483#section-2>`_.
    """
    prefix = ipaddress.ip_network(announcement.prefix)
    # A route validity state is defined by the following procedure:
    #
    # 1. Select all valid ROAs that include a ROAIPAddress value that
    #    either matches, or is a covering aggregate of, the address
    #    prefix in the route.  This selection forms the set of
    #    "candidate ROAs".
    vrp: Optional[RouteOriginAuthorization] = None
    # Lookup only returns objects that have a identical or less specific prefix.
    for vrp in lookup.lookup(announcement.prefix):
        # 3. If the route's origin AS can be determined and any of the set
        #    of candidate ROAs has an asID value that matches the origin AS
        #    in the route, and

        # announcement entries may have a string origin, but the lookup has int
        if str(vrp.asn) == str(announcement.origin):
            #    the route's address prefix matches a ROAIPAddress in the ROA
            #
            #    (where "match" is defined as where the route's address precisely
            #    matches the ROAIPAddress, or where
            if announcement.prefix == vrp.prefix:
                return "valid"
            #    the ROAIPAddress includes a maxLength element, and the route's
            #    address prefix is a more specific prefix of the ROAIPAddress,
            #    and the route's address prefix length value is less than or
            #    equal to the ROAIPAddress maxLength value), then the procedure
            #    halts with an outcome of "valid".
            elif vrp.max_length and vrp.max_length >= prefix.prefixlen:
                return "valid"
    if vrp:
        # 4. Otherwise, the procedure halts with an outcome of "invalid".
        return "invalid"
    else:
        # 2. If the set of candidate ROAs is empty, then the procedure stops
        #    with an outcome of "unknown" (or, synonymously, "not found", as
        #    used in [BGP-PFX]).
        return "unknown"


def rov_validity_verbose(
    announcement: Announcement, lookup: RouteOriginAuthorizationLookup
) -> str:
    """Verbose version of roa_validity function."""
    # Match roas, to match, they need to:
    # * have the same AS as the ROA
    # * have a prefix length <= maxLength
    roas = lookup[announcement.prefix]
    if not roas:
        return "unknown"
    was_valid = False
    for roa in roas:
        print(roa)
        if roa.asn != announcement.origin:
            LOG.info(
                "invalid as: %s ris origin: %d for %s",
                roa,
                announcement.origin,
                announcement.prefix,
            )
        else:
            assert roa.prefix_length <= announcement.prefix_length
            if roa.max_length >= announcement.prefix_length:
                LOG.info(
                    "valid roa: %s for %s announced by %s",
                    roa,
                    announcement.prefix,
                    announcement.origin,
                )
                was_valid = True
            else:
                LOG.info(
                    "invalid length: %s does not match %d",
                    announcement.prefix,
                    roa.max_length,
                )

    return "valid" if was_valid else "invalid"
