"""
Derived from the rsyncstats package [0], whose regex did not work with our rsync logs.

[0]: https://gitlab.com/resif/rsyncstats/-/tree/master
"""
import datetime
import logging
import re
from base64 import b64encode
from hashlib import sha256
from os import R_OK, access
from os.path import isfile
from typing import Dict, List, Union

import geohash2
from geolite2 import geolite2

Event = Dict[str, Union[str, Dict]]

LOG = logging.getLogger("rsynclogs")
LOG.setLevel(logging.INFO)


GLOBAL_PATTERN = re.compile(
    r"(?P<timestamp>20[0-9][0-9]/[0-9/]+ [012][0-9]:[0-5][0-9]:[0-5][0-9]) \[(?P<pid>[0-9]+)\] "
    r"(?P<logtype>(rsync (to|on)|sent)) ((?P<sentbytes>[0-9]+) bytes\s+received (?P<receivedbytes>[0-9]+) bytes\s+total size (?P<totalbytes>[0-9]+)|"
    r"(?P<module>[-\w_]+)(?P<directory>\/\S*) from (?P<hostname>\S+) \((?P<clientip>\S+)\))"
)


def iterable_log(data: str):
    """
    Generator to iterate over lines in file or in string.
    """
    if isfile(data) and access(data, R_OK):
        with open(data, "r") as loglines:
            for logline in loglines:
                yield logline.strip()
    else:
        # Consider data is the log lines to analyse
        for logline in data.split("\n"):
            yield logline


def parse_log(lines: str) -> List[Event]:
    """
    Read a rsync log file and parses information.
    Returns a list of events (dictionary).

    Aborts early when debugging
    """
    fail_count = 0
    georeader = geolite2.reader()
    events = []
    events_buffer = {}  # dict of events started but not ended. Key is the PID
    linecount = 0

    for log in lines:
        linecount += 1
        event = GLOBAL_PATTERN.search(log)
        if event is None:
            fail_count += 1
            LOG.debug("Ignoring log at %d : %s" % (linecount, log))
            if LOG.isEnabledFor(logging.DEBUG) and fail_count > 10:
                LOG.error("Aborting due to failed lines.")
                raise ValueError("Too many errors on input.")
            continue
        event_data = event.groupdict()

        # store time as epoch
        event_data["timestamp"] = datetime.datetime.strptime(
            re.sub(" +", " ", event_data["timestamp"]), "%Y/%m/%d %H:%M:%S"
        ).strftime("%Y-%m-%d %H:%M:%S")
        # 2 possible logs are captured by the pattern : connection log and transfer log.
        if event_data["logtype"] == "rsync to" or event_data["logtype"] == "rsync on":
            location = georeader.get(event_data["clientip"])
            # hash location and get the city name
            if location is not None and "location" in location:
                event_data["geohash"] = geohash2.encode(
                    location["location"]["latitude"], location["location"]["longitude"]
                )
                try:
                    event_data["city"] = location["city"]["names"]["en"]
                except KeyError:
                    event_data["city"] = ""
            else:
                event_data["geohash"] = "u0h0fpnzj9ft"
                event_data["city"] = "Grenoble"
            # hash hostname
            event_data["hosthash"] = b64encode(
                sha256(event_data["hostname"].encode()).digest()
            )[:12].decode(
                "utf-8"
            )  # overcomplicated oneliner to hash the hostname
            LOG.debug("Storing event in buffer (pid %s)" % (event_data["pid"]))
            event_data = {
                k: event_data[k] for k in event_data if event_data[k] is not None
            }
            events_buffer[event_data["pid"]] = event_data
            LOG.debug(event_data)
        elif event_data["logtype"] == "sent":
            event_data["endtime"] = event_data["timestamp"]
            # get the data from the events_buffer and merge with what we have
            try:
                previous_data = events_buffer.pop(event_data["pid"])
                events.append({**event_data, **previous_data})
            except KeyError:
                LOG.debug("Event will not be accounted : " + str(event_data))
    return events
