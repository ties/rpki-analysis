import ipaddress
from abc import ABC
from typing import Callable, TypeVar

import netaddr
import pytricia

PrefixType = str | netaddr.IPNetwork | ipaddress.IPv4Network | ipaddress.IPv6Network

V = TypeVar("V")


class BasePytriciaLookup[V](ABC):
    """
    Base type for lookup implementations.

    `__init__` should build the two tries by afi.
    """

    __trie4: pytricia.PyTricia
    __trie6: pytricia.PyTricia

    def __init__(self, initial_value: Callable[[], V] | None = None) -> None:
        self.__trie4 = pytricia.PyTricia(32)
        self.__trie6 = pytricia.PyTricia(128)

        # include 'root' element so children works
        self.__trie4["0.0.0.0/0"] = None if initial_value is None else initial_value()
        self.__trie6["::/0"] = None if initial_value is None else initial_value()

    def __contains__(self, prefix: str) -> bool:
        return prefix in self.__trie4 or prefix in self.__trie6

    def _trie(self, prefix: PrefixType) -> pytricia.PyTricia:
        """Get the relevant of trie."""
        match type(prefix):
            case netaddr.IPNetwork:
                return self.__trie6 if prefix.version == 6 else self.__trie4
            case ipaddress.IPv4Network:
                return self.__trie4
            case ipaddress.IPv6Network:
                return self.__trie6
            case _:
                return self.__trie4 if "." in prefix else self.__trie6

    def get(self, prefix: PrefixType, default=None) -> V:
        """Get the value and default to None"""
        lookup = self._trie(prefix)

        res = lookup[str(prefix)]
        if res is None:
            return default
        return res
