"""Тести перевірки даних і правила(scope CHANGED, поріг 9.0)"""

import copy

import pytest

from labs.lab04.analysis import build_report, extract_record

CVE = "CVE-2099-10001"
RULE = {"threshold": 9.0, "field": "scope", "expected": "CHANGED"}


def get_cve(payload):
    return payload["vulnerabilities"][0]["cve"]


def get_metric(payload):
    return get_cve(payload)["metrics"]["cvssMetricV31"][0]


def report(payload, variant=8):
    return build_report(extract_record(payload, CVE), CVE, variant)


def test_sample_decisions_for_all_variants(sample_payload):
    decisions = [report(sample_payload, v)["decision"] for v in range(1, 16)]
    assert decisions == ["review"] * 7 + ["other"] * 8


def test_sample_report_for_variant_8(sample_payload):
    assert report(sample_payload) == {
        "cve_id": CVE,
        "variant": 8,
        "description": "Synthetic vulnerability for offline API testing.",
        "vuln_status": "Analyzed",
        "cvss_version": "3.1",
        "score": 9.8,
        "score_source": "nvd@nist.gov",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rule": RULE,
        "observed": "UNCHANGED",
        "decision": "other",
    }


@pytest.mark.parametrize(
    "score, scope, expected",
    [
        (8.9, "CHANGED", "other"),
        (9.0, "CHANGED", "review"),
        (9.1, "CHANGED", "review"),
        (10, "UNCHANGED", "other"),
        (0, "CHANGED", "other"),
    ],
)
def test_threshold_and_scope(sample_payload, score, scope, expected):
    cvss_data = get_metric(sample_payload)["cvssData"]
    cvss_data["baseScore"] = score
    cvss_data["scope"] = scope
    assert report(sample_payload)["decision"] == expected


def test_not_found():
    assert report({"vulnerabilities": []}) == {
        "cve_id": CVE,
        "variant": 8,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": RULE,
        "observed": None,
        "decision": "not_found",
    }


def test_rejected_has_priority_over_high_score(sample_payload):
    get_cve(sample_payload)["vulnStatus"] = "Rejected"
    get_metric(sample_payload)["cvssData"].update(baseScore=10, scope="CHANGED")
    result = report(sample_payload)
    assert result["decision"] == "rejected"
    assert result["vuln_status"] == "Rejected"
    assert result["description"] == "Synthetic vulnerability for offline API testing."
    assert result["score"] is None
    assert result["observed"] is None


def test_rejected_does_not_analyze_scores(sample_payload):
    get_cve(sample_payload)["vulnStatus"] = "Rejected"
    get_cve(sample_payload)["metrics"] = None  # для rejected не перевіряється
    assert report(sample_payload)["decision"] == "rejected"


def test_missing_status_is_insufficient_data(sample_payload):
    del get_cve(sample_payload)["vulnStatus"]
    result = report(sample_payload)
    assert result["decision"] == "insufficient_data"
    assert result["vuln_status"] is None
    assert result["score"] is None
    assert result["description"] == "Synthetic vulnerability for offline API testing."


def drop_metrics(cve):
    del cve["metrics"]


def drop_v31(cve):
    del cve["metrics"]["cvssMetricV31"]


def empty_v31(cve):
    cve["metrics"]["cvssMetricV31"] = []


def only_v30(cve):
    del cve["metrics"]["cvssMetricV31"]
    cve["metrics"]["cvssMetricV30"] = [{"cvssData": {"baseScore": 9.8}}]


@pytest.mark.parametrize("change", [drop_metrics, drop_v31, empty_v31, only_v30])
def test_missing_score_is_insufficient_data(sample_payload, change):
    change(get_cve(sample_payload))
    result = report(sample_payload)
    assert result["decision"] == "insufficient_data"
    assert result["score"] is None
    assert result["observed"] is None


def test_missing_variant_field_is_insufficient_data(sample_payload):
    del get_metric(sample_payload)["cvssData"]["scope"]
    result = report(sample_payload)
    assert result["decision"] == "insufficient_data"
    assert result["score"] == 9.8
    assert result["observed"] is None


def two_metrics(payload, first_type, second_type):
    """Додати перед основною оцінкою (9.8, UNCHANGED) другу: 1.0, CHANGED"""
    first = copy.deepcopy(get_metric(payload))
    first.update(type=first_type, source="other@example.com")
    first["cvssData"].update(baseScore=1.0, scope="CHANGED")
    second = get_metric(payload)
    second["type"] = second_type
    get_cve(payload)["metrics"]["cvssMetricV31"] = [first, second]


def test_primary_has_priority_over_earlier_secondary(sample_payload):
    two_metrics(sample_payload, "Secondary", "Primary")
    result = report(sample_payload)
    assert result["score"] == 9.8
    assert result["score_source"] == "nvd@nist.gov"
    assert result["observed"] == "UNCHANGED"


def test_first_metric_is_used_without_primary(sample_payload):
    two_metrics(sample_payload, "Secondary", "Secondary")
    result = report(sample_payload)
    assert result["score"] == 1.0
    assert result["score_source"] == "other@example.com"
    assert result["observed"] == "CHANGED"


def test_first_nonempty_english_description(sample_payload):
    get_cve(sample_payload)["descriptions"] = [
        {"lang": "es", "value": "hola"},
        {"lang": "en", "value": "  "},
        {"lang": "en", "value": "Second"},
        {"lang": "en", "value": "Third"},
    ]
    assert report(sample_payload)["description"] == "Second"


def test_no_english_description(sample_payload):
    get_cve(sample_payload)["descriptions"] = [{"lang": "es", "value": "hola"}]
    assert report(sample_payload)["description"] is None


def test_optional_fields_may_be_absent(sample_payload):
    metric = get_metric(sample_payload)
    del get_cve(sample_payload)["descriptions"]
    del metric["source"]
    del metric["cvssData"]["version"]
    del metric["cvssData"]["vectorString"]
    result = report(sample_payload)
    assert result["description"] is None
    assert result["score_source"] is None
    assert result["cvss_version"] is None
    assert result["vector"] is None
    assert result["decision"] == "other"


LEVELS = {
    "cve": get_cve,
    "metrics": lambda p: get_cve(p)["metrics"],
    "metric": get_metric,
    "cvss": lambda p: get_metric(p)["cvssData"],
}

INVALID_FIELDS = [
    ("cve", "vulnStatus", None),
    ("cve", "vulnStatus", ""),
    ("cve", "vulnStatus", "  "),
    ("cve", "vulnStatus", 5),
    ("cve", "descriptions", None),
    ("cve", "descriptions", "x"),
    ("cve", "descriptions", [1]),
    ("cve", "descriptions", [{"lang": 1, "value": "x"}]),
    ("cve", "descriptions", [{"lang": "en"}]),
    ("cve", "metrics", None),
    ("cve", "metrics", []),
    ("metrics", "cvssMetricV31", None),
    ("metrics", "cvssMetricV31", {}),
    ("metrics", "cvssMetricV31", [5]),
    ("metric", "cvssData", None),
    ("metric", "cvssData", []),
    ("metric", "source", ""),
    ("metric", "source", 5),
    ("cvss", "baseScore", "9.8"),
    ("cvss", "baseScore", True),
    ("cvss", "baseScore", None),
    ("cvss", "baseScore", -0.1),
    ("cvss", "baseScore", 10.1),
    ("cvss", "baseScore", float("nan")),
    ("cvss", "baseScore", float("inf")),
    ("cvss", "version", "3.0"),
    ("cvss", "version", None),
    ("cvss", "version", ""),
    ("cvss", "vectorString", ""),
    ("cvss", "vectorString", None),
    ("cvss", "scope", None),
    ("cvss", "scope", "MAYBE"),
    ("cvss", "scope", 1),
]


@pytest.mark.parametrize("level, key, value", INVALID_FIELDS)
def test_invalid_present_field_raises(sample_payload, level, key, value):
    LEVELS[level](sample_payload)[key] = value
    with pytest.raises(ValueError):
        report(sample_payload)


@pytest.mark.parametrize("level, key", [("metric", "cvssData"), ("cvss", "baseScore")])
def test_missing_required_part_raises(sample_payload, level, key):
    del LEVELS[level](sample_payload)[key]
    with pytest.raises(ValueError):
        report(sample_payload)


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"vulnerabilities": {}},
        {"vulnerabilities": [1]},
        {"vulnerabilities": [{}]},
        {"vulnerabilities": [{"cve": {"id": "CVE-2099-99999"}}]},
        {"vulnerabilities": [{"cve": {"id": CVE}}, {"cve": {"id": CVE}}]},
    ],
)
def test_wrong_structure_raises(payload):
    with pytest.raises(ValueError):
        extract_record(payload, CVE)


@pytest.mark.parametrize("variant", [0, 16, True, "8", None])
def test_invalid_variant_raises(variant):
    with pytest.raises(ValueError):
        build_report(None, CVE, variant)


def test_payload_is_not_modified(sample_payload):
    before = copy.deepcopy(sample_payload)
    report(sample_payload)
    assert sample_payload == before
