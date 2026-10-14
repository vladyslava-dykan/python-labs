import argparse
import logging
import sys

from labs.lab02.task1 import run_demo
from labs.lab02.task2 import (
    count_query_types,
    find_anomalies,
    load_blacklist,
    read_dns_log,
    write_anomalies_csv,
)

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["demo", "analyze"])
    parser.add_argument("--dns-log")
    parser.add_argument("--blacklist")
    parser.add_argument("--out-csv", default="labs/lab02/data/dns_alerts.csv")
    parser.add_argument("--min-domain-len", type=int, default=50)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    if args.command == "demo":
        run_demo()
    else:
        if not args.dns_log or not args.blacklist:
            parser.error("для analyze потрібні --dns-log і --blacklist")

        try:
            logger.info("Parsing DNS log file %s...", args.dns_log)
            blacklist = load_blacklist(args.blacklist)
            records = list(read_dns_log(args.dns_log))
        except FileNotFoundError as error:
            logger.error("Файл не знайдено: %s", error.filename)
            sys.exit(1)
        logger.info("Processed %d DNS query records.", len(records))

        print("\n=== Query Type Breakdown ===")
        counts = count_query_types(records)
        total = len(records) or 1
        for query_type in ("A", "AAAA", "TXT", "MX"):
            count = counts[query_type]
            print(f"{query_type:<5}: {count:,} ({count / total * 100:.1f}%)")

        print("\n=== Suspicious DNS Activity ===")
        anomalies = find_anomalies(records, blacklist, args.min_domain_len)
        for anomaly in anomalies:
            record = anomaly.record
            if anomaly.blacklisted:
                print(
                    f"[BLACKMATCH] Client {record.client_ip} "
                    f"queried blacklisted domain: {record.domain}"
                )
            if anomaly.reasons:
                print(
                    f"[DGA-DETECT] {'; '.join(anomaly.reasons)}: "
                    f"{record.domain} (Client: {record.client_ip})"
                )

        if anomalies:
            logger.warning("Found %d suspicious DNS records.", len(anomalies))
        write_anomalies_csv(anomalies, args.out_csv)
        logger.info("Suspicious records exported to %s", args.out_csv)


if __name__ == "__main__":
    main()
