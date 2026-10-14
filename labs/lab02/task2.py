import csv
import logging
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

LONG_LABEL_RE = re.compile(r"[a-z0-9-]{25,}\.")
SUSPICIOUS_TLD_RE = re.compile(r"\.(xyz|top|zip|tk|click)$")


@dataclass
class DnsRecord:
    timestamp: datetime
    client_ip: str
    domain: str
    query_type: str


@dataclass
class Anomaly:
    record: DnsRecord
    blacklisted: bool
    reasons: list


def read_dns_log(path):
    with Path(path).open(encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)
        for line_number, row in enumerate(reader, start=2):
            try:
                yield DnsRecord(
                    timestamp=datetime.fromisoformat(row["Timestamp"]),
                    client_ip=row["ClientIP"].strip(),
                    domain=row["Domain"].strip().lower(),
                    query_type=row["QueryType"].strip().upper(),
                )
            except (KeyError, ValueError, AttributeError):
                logger.warning("Пропущено некоректний рядок %d", line_number)


def load_blacklist(path):
    with Path(path).open(encoding="utf-8") as file:
        return {line.strip().lower() for line in file if line.strip()}


def is_blacklisted(domain, blacklist):
    return any(domain == bad or domain.endswith("." + bad) for bad in blacklist)


def count_query_types(records):
    return Counter(record.query_type for record in records)


def find_suspicious_reasons(domain, min_domain_len):
    reasons = []
    if LONG_LABEL_RE.search(domain):
        reasons.append("Suspicious long subdomain")
    if SUSPICIOUS_TLD_RE.search(domain):
        reasons.append("Suspicious TLD")
    if len(domain) >= min_domain_len:
        reasons.append(f"Abnormally long domain (Length: {len(domain)})")
    return reasons


def find_anomalies(records, blacklist, min_domain_len):
    anomalies = []
    for record in records:
        blacklisted = is_blacklisted(record.domain, blacklist)
        reasons = find_suspicious_reasons(record.domain, min_domain_len)
        if blacklisted or reasons:
            anomalies.append(Anomaly(record, blacklisted, reasons))
    return anomalies


def write_anomalies_csv(anomalies, path):
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "ClientIP", "Domain", "QueryType", "Reason"])
        for anomaly in anomalies:
            record = anomaly.record
            parts = (["Blacklisted domain"] if anomaly.blacklisted else []) + (
                anomaly.reasons
            )
            writer.writerow(
                [
                    record.timestamp.isoformat(),
                    record.client_ip,
                    record.domain,
                    record.query_type,
                    "; ".join(parts),
                ]
            )
