"""Параметризовані SQL-запити до таблиць categories і records"""

import sqlite3
from contextlib import closing

from labs.lab03.database import get_connection


class NotFoundError(Exception):
    """Запис або категорію не знайдено."""


def _connect() -> sqlite3.Connection:
    """Відкрити з'єднання, рядки результатів доступні за назвами полів"""
    connection = get_connection()
    connection.row_factory = sqlite3.Row
    return connection


def create_category(name: str) -> dict:
    """Створити категорію. Дублікат назви дає sqlite3.IntegrityError"""
    with closing(_connect()) as connection:
        with connection:
            cursor = connection.execute(
                "INSERT INTO categories (name) VALUES (?)", (name,)
            )
        return {"id": cursor.lastrowid, "name": name}


def list_categories() -> list[dict]:
    """Повернути всі категорії за зростанням id"""
    with closing(_connect()) as connection:
        rows = connection.execute(
            "SELECT id, name FROM categories ORDER BY id"
        ).fetchall()
    return [dict(row) for row in rows]


def delete_category(category_id: int) -> None:
    """Видалити порожню категорію. Непорожня дає sqlite3.IntegrityError"""
    with closing(_connect()) as connection:
        with connection:
            cursor = connection.execute(
                "DELETE FROM categories WHERE id = ?", (category_id,)
            )
        if cursor.rowcount == 0:
            raise NotFoundError("Категорію не знайдено")


RECORD_SELECT = (
    "SELECT r.id, r.code, r.title, r.category_id, c.name AS category_name, "
    "r.value, r.status "
    "FROM records AS r JOIN categories AS c ON c.id = r.category_id"
)


def _check_category(connection: sqlite3.Connection, category_id: int) -> None:
    """Перевірити, що категорія існує, інакше NotFoundError"""
    row = connection.execute(
        "SELECT 1 FROM categories WHERE id = ?", (category_id,)
    ).fetchone()
    if row is None:
        raise NotFoundError("Категорію не знайдено")


def _fetch_record(connection: sqlite3.Connection, record_id: int) -> dict:
    """Прочитати запис разом з назвою категорії (JOIN)."""
    row = connection.execute(RECORD_SELECT + " WHERE r.id = ?", (record_id,)).fetchone()
    if row is None:
        raise NotFoundError("Запис не знайдено")
    return dict(row)


def create_record(data: dict) -> dict:
    """Додати запис. Дублікат code дає sqlite3.IntegrityError"""
    with closing(_connect()) as connection:
        _check_category(connection, data["category_id"])
        with connection:
            cursor = connection.execute(
                "INSERT INTO records (code, title, category_id, value, status) "
                "VALUES (:code, :title, :category_id, :value, :status)",
                data,
            )
        return _fetch_record(connection, cursor.lastrowid)


def get_record(record_id: int) -> dict:
    with closing(_connect()) as connection:
        return _fetch_record(connection, record_id)


def delete_record(record_id: int) -> None:
    """Видалити запис за id"""
    with closing(_connect()) as connection:
        with connection:
            cursor = connection.execute(
                "DELETE FROM records WHERE id = ?", (record_id,)
            )
        if cursor.rowcount == 0:
            raise NotFoundError("Запис не знайдено")


def list_records(
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict]:
    """Повернути записи з фільтрами і сторінками, за зростанням id"""
    conditions = []
    params = []
    if category_id is not None:
        conditions.append("r.category_id = ?")
        params.append(category_id)
    if status is not None:
        conditions.append("r.status = ?")
        params.append(status)
    if min_value is not None:
        conditions.append("r.value >= ?")
        params.append(min_value)
    if q is not None:
        conditions.append("instr(r.title, ?) > 0")
        params.append(q)

    sql = RECORD_SELECT
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    sql += " ORDER BY r.id LIMIT ? OFFSET ?"
    params += [limit, offset]

    with closing(_connect()) as connection:
        rows = connection.execute(sql, params).fetchall()
    return [dict(row) for row in rows]


def replace_record(record_id: int, data: dict) -> dict:
    """Замінити всі змінювані поля запису. id не змінюється"""
    with closing(_connect()) as connection:
        _fetch_record(connection, record_id)
        _check_category(connection, data["category_id"])
        with connection:
            connection.execute(
                "UPDATE records SET code = :code, title = :title, "
                "category_id = :category_id, value = :value, status = :status "
                "WHERE id = :id",
                {**data, "id": record_id},
            )
        return _fetch_record(connection, record_id)


def create_records_bulk(items: list[dict]) -> list[dict]:
    """Додати всі записи однією транзакцією: або всі, або жодного"""
    with closing(_connect()) as connection:
        for item in items:
            _check_category(connection, item["category_id"])
        record_ids = []
        with connection:
            for item in items:
                cursor = connection.execute(
                    "INSERT INTO records (code, title, category_id, value, status) "
                    "VALUES (:code, :title, :category_id, :value, :status)",
                    item,
                )
                record_ids.append(cursor.lastrowid)
        return [_fetch_record(connection, record_id) for record_id in record_ids]
