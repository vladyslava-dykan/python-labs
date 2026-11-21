"""Консольна утиліта: запис про вразливість з NVD та звіт за правилом варіанта"""

import argparse
import json
import re
import sys
from pathlib import Path

import requests

from labs.lab04 import analysis, api_client
from shared.student import VARIANT_NUMBER

CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def cve_id_type(value: str) -> str:
    """Перевірити, що ідентифікатор повністю збігається з шаблоном CVE"""
    if not CVE_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError(f"некоректний CVE-ідентифікатор: {value!r}")
    return value


def build_parser() -> argparse.ArgumentParser:
    """Створити обробник команд"""
    parser = argparse.ArgumentParser(description="Перегляд запису CVE з NVD")
    parser.add_argument(
        "--cve",
        required=True,
        type=cve_id_type,
        help="ідентифікатор, наприклад CVE-2021-44228",
    )
    parser.add_argument(
        "--input", help="шлях до локальної відповіді NVD (UTF-8 JSON), без мережі"
    )
    return parser


def load_response(path: str) -> object:
    """Прочитати локальну відповідь NVD з UTF-8 JSON-файлу"""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _variant_is_valid(variant: object) -> bool:
    """Номер варіанта: ціле число (не bool) від 1 до 15"""
    return (
        isinstance(variant, int)
        and not isinstance(variant, bool)
        and 1 <= variant <= 15
    )


def _fail(message: str) -> int:
    """Вивести повідомлення про помилку в stderr і повернути код 1"""
    print(f"Помилка: {message}", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    """Виконати програму й повернути код завершення (0, 1 або 2)"""
    variant = VARIANT_NUMBER
    if not _variant_is_valid(variant):
        message = "номер варіанта має бути цілим числом від 1 до 15"
        print(f"Помилка: {message}", file=sys.stderr)
        return 2

    args = build_parser().parse_args(argv)
    try:
        if args.input is not None:
            payload = load_response(args.input)
        else:
            payload = api_client.fetch_response(args.cve)
        record = analysis.extract_record(payload, args.cve)
        report = analysis.build_report(record, args.cve, variant)
    except requests.exceptions.Timeout:
        return _fail("перевищено час очікування відповіді NVD")
    except requests.exceptions.ConnectionError:
        return _fail("не вдалося з'єднатися з NVD")
    except requests.exceptions.HTTPError as error:
        status = getattr(error.response, "status_code", "невідомий")
        return _fail(f"NVD повернув неочікуваний HTTP-статус: {status}")
    except (json.JSONDecodeError, requests.exceptions.JSONDecodeError):
        return _fail("відповідь не є коректним JSON")
    except requests.exceptions.RequestException:
        return _fail("помилка мережевого запиту")
    except OSError:
        return _fail("не вдалося прочитати файл із відповіддю")
    except ValueError as error:
        return _fail(f"некоректні дані: {error}")

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
