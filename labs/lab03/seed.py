"""Початкове заповнення бази даними з seed.json"""

import json
import sqlite3
from contextlib import closing
from pathlib import Path

from labs.lab03.database import get_connection, initialize_database

SEED_PATH = Path(__file__).resolve().parent / "data" / "seed.json"


def load_seed() -> dict:
    """Прочитати JSON і перевірити, що в ньому є списки categories і records"""
    data = json.loads(SEED_PATH.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError("JSON має бути об'єктом")
    for key in ("categories", "records"):
        if not isinstance(data.get(key), list):
            raise TypeError(f"У JSON немає списку {key}")
    return data


def seed_database() -> None:
    """Заповнити порожню базу однією транзакцією"""
    initialize_database()
    try:
        data = load_seed()
    except (OSError, ValueError, TypeError) as error:
        print(f"Некоректні початкові дані: {error}")
        return

    with closing(get_connection()) as connection:
        total = connection.execute(
            "SELECT (SELECT COUNT(*) FROM categories) + (SELECT COUNT(*) FROM records)"
        ).fetchone()[0]
        if total > 0:
            print("База вже містить дані, заповнення пропущено")
            return

        try:
            with connection:
                connection.executemany(
                    "INSERT INTO categories (id, name) VALUES (:id, :name)",
                    data["categories"],
                )
                connection.executemany(
                    "INSERT INTO records (code, title, category_id, value, status) "
                    "VALUES (:code, :title, :category_id, :value, :status)",
                    data["records"],
                )
        except sqlite3.Error as error:
            print(f"Помилка заповнення, усі зміни скасовано: {error}")
            return

    print(
        f"Додано {len(data['categories'])} категорії та {len(data['records'])} записів"
    )


if __name__ == "__main__":
    seed_database()
