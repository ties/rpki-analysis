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
import sys

import polars as pl
import requests

from rpki_analysis.delegated_stats import normalized_delegated_extended_stats

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

NRO_STATS_URL = (
    "https://ftp.ripe.net/pub/stats/ripencc/nro-stats/latest/nro-delegated-stats"
)
OUTPUT_PARQUET_FILE = "nro-delegated-extended.parquet"
TEMP_DOWNLOAD_FILE = "nro-delegated-stats.txt"


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
    # Download the NRO delegated stats file
    if not download_file(NRO_STATS_URL, TEMP_DOWNLOAD_FILE):
        logging.error("Failed to download NRO stats. Exiting.")
        sys.exit(1)

    logging.info(f"Parsing {TEMP_DOWNLOAD_FILE}...")
    df = normalized_delegated_extended_stats(TEMP_DOWNLOAD_FILE).collect()
    logging.info("Successfully parsed the NRO stats file.")

    df.write_parquet(OUTPUT_PARQUET_FILE)
    logging.info(f"Successfully saved DataFrame to {OUTPUT_PARQUET_FILE}")

    import os

    os.remove(TEMP_DOWNLOAD_FILE)
    logging.info(f"Removed temporary file {TEMP_DOWNLOAD_FILE}.")

    logging.info("Script finished successfully.")


if __name__ == "__main__":
    main()
