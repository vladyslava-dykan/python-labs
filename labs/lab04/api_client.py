"""HTTP-клієнт для NVD CVE API 2.0"""

import os

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT = (3.05, 10)


def build_headers() -> dict[str, str]:
    """Повернути заголовки запиту; apiKey додається лише за наявності ключа"""
    headers = {"Accept": "application/json"}
    api_key = os.getenv("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key
    return headers


def fetch_response(cve_id: str) -> object:
    """Виконати один GET-запит до NVD і повернути декодований JSON"""
    response = requests.get(
        NVD_URL,
        params={"cveId": cve_id},
        headers=build_headers(),
        timeout=TIMEOUT,
        allow_redirects=False,
    )
    response.raise_for_status()
    if response.status_code != 200:
        raise requests.exceptions.HTTPError(
            f"Неочікуваний статус {response.status_code}", response=response
        )
    return response.json()
