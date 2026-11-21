"""Тести HTTP-клієнта: requests.get підмінено, мережі немає"""

from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client

CVE = "CVE-2099-10001"
URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def make_response(status_code=200, payload=None):
    response = Mock(spec=requests.Response)
    response.status_code = status_code
    response.json.return_value = payload
    return response


def patch_get(monkeypatch, **kwargs):
    fake_get = Mock(**kwargs)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    return fake_get


def test_headers_without_key():
    assert api_client.build_headers() == {"Accept": "application/json"}


@pytest.mark.parametrize("value", ["", "   "])
def test_blank_key_means_no_key(monkeypatch, value):
    monkeypatch.setenv("NVD_API_KEY", value)
    assert api_client.build_headers() == {"Accept": "application/json"}


@pytest.mark.parametrize("value", ["fake-key", "  fake-key  "])
def test_headers_with_fake_key(monkeypatch, value):
    monkeypatch.setenv("NVD_API_KEY", value)
    assert api_client.build_headers() == {
        "Accept": "application/json",
        "apiKey": "fake-key",
    }


def test_fetch_uses_expected_request(monkeypatch):
    payload = {"startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    response = make_response(200, payload)
    fake_get = patch_get(monkeypatch, return_value=response)

    assert api_client.fetch_response(CVE) == payload
    fake_get.assert_called_once_with(
        URL,
        params={"cveId": CVE},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


def test_key_goes_to_header_not_to_url(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "fake-key")
    fake_get = patch_get(monkeypatch, return_value=make_response(200, {}))

    api_client.fetch_response(CVE)

    kwargs = fake_get.call_args.kwargs
    assert kwargs["headers"] == {"Accept": "application/json", "apiKey": "fake-key"}
    assert kwargs["params"] == {"cveId": CVE}
    assert fake_get.call_args.args == (URL,)


@pytest.mark.parametrize("status", [404, 500])
def test_http_error_is_raised(monkeypatch, status):
    response = make_response(status)
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "error", response=response
    )
    patch_get(monkeypatch, return_value=response)

    with pytest.raises(requests.exceptions.HTTPError) as info:
        api_client.fetch_response(CVE)
    assert info.value.response.status_code == status


@pytest.mark.parametrize("status", [204, 302])
def test_unexpected_status_is_error(monkeypatch, status):
    patch_get(monkeypatch, return_value=make_response(status, {}))

    with pytest.raises(requests.exceptions.HTTPError) as info:
        api_client.fetch_response(CVE)
    assert info.value.response.status_code == status


def test_invalid_json_is_raised(monkeypatch):
    response = make_response(200)
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "{", 1
    )
    patch_get(monkeypatch, return_value=response)

    with pytest.raises(requests.exceptions.JSONDecodeError):
        api_client.fetch_response(CVE)


@pytest.mark.parametrize(
    "error",
    [requests.exceptions.Timeout("t"), requests.exceptions.ConnectionError("c")],
)
def test_network_error_is_raised(monkeypatch, error):
    fake_get = patch_get(monkeypatch, side_effect=error)

    with pytest.raises(type(error)):
        api_client.fetch_response(CVE)
    kwargs = fake_get.call_args.kwargs
    assert kwargs["params"] == {"cveId": CVE}
    assert kwargs["timeout"] == (3.05, 10)
