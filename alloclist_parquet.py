#!/usr/bin/env -S uv run --with .
# /// script
# requires-python = ">=3.13"
# dependencies = [
#   "requests",
#   "polars>=1.29.0",
# ]
# ///
#
import logging
import os
import sys

import requests

from rpki_analysis.alloclist import ALLOCLIST_URL, read_alloclist

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

OUTPUT_PARQUET_FILE = "alloclist.parquet"
TEMP_DOWNLOAD_FILE = "alloclist.txt"


def download_file(url: str, local_filename: str) -> bool:
    """Downloads a file from a URL to a local path."""
    logging.info(f"Downloading {url} to {local_filename}...")
    try:
        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            with open(local_filename, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        logging.info(f"Successfully downloaded {local_filename}")
        return True
    except requests.exceptions.RequestException as e:
        logging.error(f"Error downloading {url}: {e}")
        return False


def main():
    """Main script execution."""
    # Download the alloclist file
    if not download_file(ALLOCLIST_URL, TEMP_DOWNLOAD_FILE):
        logging.error("Failed to download alloclist. Exiting.")
        sys.exit(1)

    logging.info(f"Parsing {TEMP_DOWNLOAD_FILE}...")
    with open(TEMP_DOWNLOAD_FILE) as f:
        df = read_alloclist(f)
    logging.info("Successfully parsed the alloclist file.")

    df.write_parquet(OUTPUT_PARQUET_FILE)
    logging.info(f"Successfully saved DataFrame to {OUTPUT_PARQUET_FILE}")

    os.remove(TEMP_DOWNLOAD_FILE)
    logging.info(f"Removed temporary file {TEMP_DOWNLOAD_FILE}.")

    logging.info("Script finished successfully.")


if __name__ == "__main__":
    main()
