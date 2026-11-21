"""Тести командного інтерфейсу. Файл, підміна клієнта, коди завершення"""

import json
from pathlib import Path
from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import main

CVE = "CVE-2099-10001"
SAMPLE_PATH = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"
LOCAL_ARGS = ["--cve", CVE, "--input", str(SAMPLE_PATH)]


@pytest.fixture
def fake_fetch(monkeypatch):
    """Підміна функції отримання даних: мережі немає, виклики видно"""
    fake = Mock(name="fetch_response")
    monkeypatch.setattr(main.api_client, "fetch_response", fake)
    return fake


def test_local_run_prints_one_json_report(capsys, fake_fetch):
    assert main.main(LOCAL_ARGS) == 0

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["cve_id"] == CVE
    assert report["variant"] == 8
    assert report["score"] == 9.8
    assert report["observed"] == "UNCHANGED"
    assert report["decision"] == "other"
    assert captured.err == ""
    fake_fetch.assert_not_called()


def test_variant_is_taken_from_module_name(monkeypatch, capsys):
    monkeypatch.setattr(main, "VARIANT_NUMBER", 1)
    assert main.main(LOCAL_ARGS) == 0

    report = json.loads(capsys.readouterr().out)
    assert report["variant"] == 1
    assert report["decision"] == "review"


def test_ukrainian_text_is_not_escaped(tmp_path, capsys, sample_payload):
    sample_payload["vulnerabilities"][0]["cve"]["descriptions"][0]["value"] = "Опис"
    path = tmp_path / "ua.json"
    path.write_text(json.dumps(sample_payload, ensure_ascii=False), encoding="utf-8")

    assert main.main(["--cve", CVE, "--input", str(path)]) == 0
    assert '"description": "Опис"' in capsys.readouterr().out


def test_not_found_is_success_with_report(tmp_path, capsys):
    path = tmp_path / "empty.json"
    path.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")

    assert main.main(["--cve", CVE, "--input", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "not_found"


def test_missing_file(tmp_path, capsys):
    args = ["--cve", CVE, "--input", str(tmp_path / "nope.json")]
    assert main.main(args) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Помилка: не вдалося прочитати файл" in captured.err


@pytest.mark.parametrize("text", ["{ not json", "{}", "[]"])
def test_bad_file_content(tmp_path, capsys, text):
    path = tmp_path / "bad.json"
    path.write_text(text, encoding="utf-8")

    assert main.main(["--cve", CVE, "--input", str(path)]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("Помилка:")
    assert "Traceback" not in captured.err


def test_empty_input_path_is_not_network_mode(capsys, fake_fetch):
    assert main.main(["--cve", CVE, "--input", ""]) == 1
    assert capsys.readouterr().out == ""
    fake_fetch.assert_not_called()


def test_response_for_other_cve_is_error(capsys):
    assert main.main(["--cve", "CVE-2099-10002", "--input", str(SAMPLE_PATH)]) == 1
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    "cve", ["cve-2099-10001", "CVE-2099-123", "CVE-99-10001", "CVE-2099-10001 ", ""]
)
def test_invalid_cve_argument_exits_with_2(cve, capsys):
    with pytest.raises(SystemExit) as info:
        main.main(["--cve", cve])
    assert info.value.code == 2
    assert capsys.readouterr().err != ""


def test_missing_cve_argument_exits_with_2():
    with pytest.raises(SystemExit) as info:
        main.main([])
    assert info.value.code == 2


@pytest.mark.parametrize("variant", [0, 16, True, "8", None])
def test_invalid_variant_returns_2(monkeypatch, capsys, variant):
    monkeypatch.setattr(main, "VARIANT_NUMBER", variant)
    assert main.main(LOCAL_ARGS) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "варіанта" in captured.err


def test_without_input_data_comes_from_client(capsys, fake_fetch, sample_payload):
    fake_fetch.return_value = sample_payload

    assert main.main(["--cve", CVE]) == 0
    fake_fetch.assert_called_once_with(CVE)
    assert json.loads(capsys.readouterr().out)["decision"] == "other"


def http_error(status):
    response = Mock(status_code=status)
    return requests.exceptions.HTTPError("secret-detail", response=response)


@pytest.mark.parametrize(
    "error, text",
    [
        (requests.exceptions.ReadTimeout("secret-detail"), "час очікування"),
        (requests.exceptions.ConnectTimeout("secret-detail"), "час очікування"),
        (requests.exceptions.ConnectionError("secret-detail"), "з'єднатися"),
        (http_error(404), "HTTP-статус: 404"),
        (http_error(500), "HTTP-статус: 500"),
        (requests.exceptions.JSONDecodeError("secret-detail", "{", 1), "JSON"),
        (requests.exceptions.InvalidURL("secret-detail"), "мережевого запиту"),
    ],
)
def test_network_errors_give_code_1_without_details(
    monkeypatch, capsys, fake_fetch, error, text
):
    monkeypatch.setenv("NVD_API_KEY", "fake-secret")
    fake_fetch.side_effect = error

    assert main.main(["--cve", CVE]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert text in captured.err
    assert "secret" not in captured.err
    assert "Traceback" not in captured.err
