"""
Parse S3 log files and get field level statistics
"""

import argparse
import glob
import gzip
import itertools
import logging
import sys
import urllib
from typing import Any, List, Optional

import pandas as pd

logging.basicConfig()

LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)

VERSION_MARKER = "#Version: 1.0"
FIELDS_MARKER = "#Fields: "


def fields_from_file(csvfile: str) -> List[str]:
    """Get the fieldnames from a file."""
    header = csvfile.readline().strip()
    if header != VERSION_MARKER:
        LOG.error("Version line '%s' in %s", header, csvfile.name)
    assert header == VERSION_MARKER

    field_line = csvfile.readline().strip()
    assert field_line.startswith(FIELDS_MARKER)

    return field_line[len(FIELDS_MARKER) :].split(" ")


def read_file(
    file_name: str,
    usecols: Optional[List[str]] = None,
    filter_func: Optional[Any] = None,
) -> pd.DataFrame:

    with (
        gzip.open(file_name, "rt")
        if file_name.endswith(".gz")
        else open(file_name, "r")
    ) as csvfile:
        # Get fields for this specific file
        fields = fields_from_file(csvfile)
        # Seek back to beginning
        csvfile.seek(0)

        try:
            this_df = pd.read_csv(
                csvfile,
                names=fields,
                delimiter="\t",
                header=0,
                skiprows=2,
                usecols=usecols,
                engine="c",
            )
            if "cs(User-Agent)" in this_df:
                this_df["cs(User-Agent)"] = this_df["cs(User-Agent)"].map(
                    urllib.parse.unquote
                )
            this_df["datetime"] = pd.to_datetime(this_df.date + " " + this_df.time)
        except:  # noqa: E722
            LOG.exception("Could not read %s", file_name)
            raise

        if filter_func:
            this_df = filter_func(this_df)

        return this_df


# TODO: reduce dataframes after each is read?
def read_from_glob(
    globs: List[str],
    usecols: Optional[List[str]] = None,
    filter_func: Optional[Any] = None,
    final_func: Optional[Any] = None,
) -> pd.DataFrame:
    """
    `filter_func` is applied to every dataframe to filter the data before building the final frame.
    """
    dfs = []

    file_names = list(itertools.chain.from_iterable(map(glob.glob, globs)))

    failures = 0

    for file in file_names:
        # Append takes the union of the columns
        try:
            dfs.append(read_file(file, usecols, filter_func))
        except:  # noqa: E722
            if failures < 5:
                LOG.exception("Failed to read %s", file)
            failures += 1

    LOG.info("Read %d/%d files", len(file_names) - failures, len(file_names))

    df = pd.concat(dfs)
    # Allow it to be gc-ed
    del dfs

    LOG.info("rows: %d, columns: %d", df.shape[0], df.shape[1])

    if final_func:
        df = final_func(df)

    LOG.info(df.memory_usage(deep=True))
    LOG.info(df.dtypes)

    return df


def main(aggregate_fields: List[str], globs: List[str]):
    df = read_from_glob(globs, usecols=aggregate_fields)

    fields = df.keys()

    if not aggregate_fields:
        print("Provide fields to group by via --fields")
        print(f"options: {', '.join(fields)}")
        sys.exit(1)

    if not set(aggregate_fields).issubset(set(fields)):
        print(f"Unknown fields: {', '.join(set(aggregate_fields) - set(fields))}")
        print(f"known fields: {', '.join(fields)}")
        sys.exit(1)

    # Add dummy column
    df["count"] = 1

    stats = df.groupby(aggregate_fields).count()
    # Full output
    pd.set_option("display.max_rows", None, "display.max_columns", None)
    print(stats)


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Cloudfront log statistics")
    parser.add_argument("files", type=str, nargs="+", help="Logfiles to parse")

    parser.add_argument(
        "-f",
        "--field",
        type=str,
        action="append",
        dest="fields",
        help="Field to aggregate by",
    )

    args = parser.parse_args()

    main(args.fields, args.files)
