"""Перевірка відповіді NVD і правило аналізу за варіантом."""

# Правила варіантів: (поріг T, поле cvssData, очікуване значення)
RULES = {
    1: (7.0, "attackVector", "NETWORK"),
    2: (8.0, "attackComplexity", "LOW"),
    3: (7.0, "privilegesRequired", "NONE"),
    4: (8.0, "userInteraction", "NONE"),
    5: (7.0, "confidentialityImpact", "HIGH"),
    6: (7.0, "integrityImpact", "HIGH"),
    7: (7.0, "availabilityImpact", "HIGH"),
    8: (9.0, "scope", "CHANGED"),
    9: (5.0, "attackVector", "LOCAL"),
    10: (6.0, "privilegesRequired", "LOW"),
    11: (6.0, "userInteraction", "REQUIRED"),
    12: (6.0, "confidentialityImpact", "LOW"),
    13: (6.0, "integrityImpact", "LOW"),
    14: (6.0, "availabilityImpact", "LOW"),
    15: (8.0, "attackComplexity", "HIGH"),
}

# Допустимі значення полів cvssData (таблиця розділу 2.2 методички)
LEVEL = {"NONE", "LOW", "HIGH"}
ALLOWED_VALUES = {
    "attackVector": {"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"},
    "attackComplexity": {"LOW", "HIGH"},
    "privilegesRequired": LEVEL,
    "userInteraction": {"NONE", "REQUIRED"},
    "scope": {"UNCHANGED", "CHANGED"},
    "confidentialityImpact": LEVEL,
    "integrityImpact": LEVEL,
    "availabilityImpact": LEVEL,
}


def _require(condition: bool, message: str) -> None:
    """Піднести ValueError із повідомленням, якщо умова не виконується."""
    if not condition:
        raise ValueError(message)


def _optional_text(container: dict, key: str) -> str | None:
    """Відсутній ключ дає None; наявний має бути непорожнім рядком."""
    if key not in container:
        return None
    value = container[key]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Поле {key} має бути непорожнім рядком")
    return value


def _english_description(cve: dict) -> str | None:
    """Перший непорожній опис англійською або None."""
    if "descriptions" not in cve:
        return None
    items = cve["descriptions"]
    _require(isinstance(items, list), "descriptions має бути списком")
    result = None
    for item in items:
        _require(isinstance(item, dict), "Елемент descriptions має бути об'єктом")
        lang, value = item.get("lang"), item.get("value")
        _require(
            isinstance(lang, str) and isinstance(value, str),
            "lang і value в descriptions мають бути рядками",
        )
        if result is None and lang == "en" and value.strip():
            result = value
    return result


def _select_metric(cve: dict) -> dict | None:
    """Перший елемент Primary зі списку cvssMetricV31, інакше перший; або None."""
    if "metrics" not in cve:
        return None
    metrics = cve["metrics"]
    _require(isinstance(metrics, dict), "metrics має бути об'єктом")
    if "cvssMetricV31" not in metrics:
        return None
    items = metrics["cvssMetricV31"]
    _require(isinstance(items, list), "cvssMetricV31 має бути списком")
    if not items:
        return None
    _require(
        all(isinstance(item, dict) for item in items),
        "Елементи cvssMetricV31 мають бути об'єктами",
    )
    return next((item for item in items if item.get("type") == "Primary"), items[0])


def _check_score(score: object) -> None:
    """Оцінка: число (не bool) від 0 до 10. NaN та нескінченність не проходять."""
    _require(
        isinstance(score, (int, float)) and not isinstance(score, bool),
        "baseScore має бути числом",
    )
    _require(0 <= score <= 10, "baseScore має бути скінченним числом від 0 до 10")


def extract_record(payload: object, cve_id: str) -> dict | None:
    """Перевірити відповідь NVD і повернути внутрішній запис або None.

    Запис (словник): status, description, score, source, version, vector
    (рядки/число або None) та cvss_data (копія вибраного cvssData або None).
    Для статусу Rejected чи відсутнього статусу оцінки не аналізуються.
    Порушення структури даних дає ValueError.
    """
    _require(
        isinstance(payload, dict) and isinstance(payload.get("vulnerabilities"), list),
        "Відповідь має містити список vulnerabilities",
    )
    items = payload["vulnerabilities"]
    if not items:
        return None
    if len(items) > 1:
        raise ValueError("Очікується не більше одного запису")
    cve = items[0].get("cve") if isinstance(items[0], dict) else None
    if not isinstance(cve, dict) or cve.get("id") != cve_id:
        raise ValueError("Запис не містить cve із запитаним id")

    record = {
        "status": _optional_text(cve, "vulnStatus"),
        "description": _english_description(cve),
        "score": None,
        "source": None,
        "version": None,
        "vector": None,
        "cvss_data": None,
    }
    if record["status"] in (None, "Rejected"):
        return record
    metric = _select_metric(cve)
    if metric is None:
        return record

    cvss_data = metric.get("cvssData")
    _require(isinstance(cvss_data, dict), "cvssData має бути об'єктом")
    _check_score(cvss_data.get("baseScore"))
    version = _optional_text(cvss_data, "version")
    if version not in (None, "3.1"):
        raise ValueError("Підтримується лише CVSS версії 3.1")
    record.update(
        score=cvss_data["baseScore"],
        source=_optional_text(metric, "source"),
        version=version,
        vector=_optional_text(cvss_data, "vectorString"),
        cvss_data=dict(cvss_data),
    )
    return record


def build_report(record: dict | None, cve_id: str, variant: int) -> dict:
    """Застосувати правило варіанта й повернути словник звіту."""
    if isinstance(variant, bool) or variant not in RULES:
        raise ValueError("Невідомий номер варіанта")
    threshold, field, expected = RULES[variant]
    report = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {"threshold": threshold, "field": field, "expected": expected},
        "observed": None,
        "decision": "not_found",
    }
    if record is None:
        return report

    report["description"] = record["description"]
    report["vuln_status"] = record["status"]
    if record["status"] == "Rejected":
        report["decision"] = "rejected"
        return report
    report["decision"] = "insufficient_data"
    if record["status"] is None or record["score"] is None:
        return report

    report["cvss_version"] = record["version"]
    report["score"] = record["score"]
    report["score_source"] = record["source"]
    report["vector"] = record["vector"]
    if field not in record["cvss_data"]:
        return report
    observed = record["cvss_data"][field]
    if not isinstance(observed, str) or observed not in ALLOWED_VALUES[field]:
        raise ValueError(f"Недопустиме значення поля {field}")
    report["observed"] = observed
    is_review = record["score"] >= threshold and observed == expected
    report["decision"] = "review" if is_review else "other"
    return report
