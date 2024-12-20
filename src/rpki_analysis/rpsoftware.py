import re
from typing import Optional, Pattern

import pandas as pd

__ALL__ = ["group_clients", "detailed_group_clients", "RP_SOFTWARE"]


class RP:
    name: str
    pattern: Pattern
    static_version: Optional[str] = None

    def __init__(self, name: str, pattern: str, static_version: Optional[str] = None):
        self.name = name
        self.pattern = re.compile(pattern)
        self.static_version = static_version

    def matches(self, inp: str) -> bool:
        return self.pattern.match(inp)

    def version(self, inp: str) -> Optional[str]:
        match = self.pattern.match(inp)

        if match:
            if self.static_version:
                return self.static_version
            return match.group(1)


RP_IMPLEMENTATIONS = frozenset(
    [
        RP("routinator", r".*reqwest.*", "<= 0.6.4"),
        RP("routinator", r"Routinator(?:[/ ])(.*)"),
        RP("validator3", r".*Jetty.*", "unknown"),
        RP("validator3", r".*Validator/(.*)"),
        RP("fort", r"fort/(.*)"),
        RP("octorpki", r"Cloudflare-(?:RPKI-RRDP/|RRDP-OctoRPKI)(.*) \(.*"),
        RP("rpki-client", r"(.*(?:rpki-client).*)"),
        RP("rpki-prover", r"rpki-prover-(.*)"),
        RP("rpki-monitoring", r"rpki-monitor (?:rpki-monitoring-)(.*)"),
        # Shao Qinq, 2021-04-02, #hallway-chat on Discord
        RP("rpstir2", r".*Chrome\/72.0.3626.109 Safari\/537.36(?: )?(RPSTIR2|)?.*"),
        RP("blackbox-exporter", r"Go-http-client/(2.0)"),
        RP("validator2", r".*Apache-HttpClient.*", "unknown"),
    ]
)

RP_SOFTWARE = frozenset(rp.name for rp in RP_IMPLEMENTATIONS)


def group_clients(user_agent):
    for rp in RP_IMPLEMENTATIONS:
        if rp.matches(user_agent):
            return rp.name
    return "unknown"


def detailed_group_clients(user_agent):
    for rp in RP_IMPLEMENTATIONS:
        version = rp.version(user_agent)
        if version:
            return version
    return "unknown"


class RRDPUrlMatcher:
    # https://rrdp.ripe.net/64553070-e947-46aa-8193-794d03adef75/474/delta.xml
    URL_RE = re.compile("/(?P<session>.*-.*-.*-.*-.*)/(?P<serial>.*)/(?P<file>.*).xml")

    def __init__(self, field):
        assert field in ("session", "serial", "file")
        self.field = field

    def __call__(self, inp) -> dict:
        res = self.URL_RE.match(inp)
        if res:
            return res.group(self.field)
        elif self.field == "session":
            if inp == "/notification.xml":
                return "notification"
