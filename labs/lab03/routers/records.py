"""Маршрути для записів"""

import sqlite3
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Path, Query

from labs.lab03 import repository
from labs.lab03.config import VALUE_MIN
from labs.lab03.schemas import RecordBatch, RecordCreate, RecordRead, RecordReplace

router = APIRouter(prefix="/records", tags=["records"])


@router.get("", response_model=list[RecordRead], summary="Список записів")
def list_records(
    category_id: Annotated[
        int | None, Query(gt=0, description="Лише записи цієї категорії")
    ] = None,
    status: Annotated[
        Literal["new", "in_progress", "done"] | None,
        Query(description="Лише записи з цим статусом"),
    ] = None,
    min_value: Annotated[
        float | None,
        Query(
            ge=VALUE_MIN,
            allow_inf_nan=False,
            description="Лише записи, де value не менше за це число (хвилини)",
        ),
    ] = None,
    q: Annotated[
        str | None,
        Query(
            min_length=1,
            max_length=120,
            description="Підрядок у title (з урахуванням регістру)",
        ),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=100, description="Максимум записів")] = 20,
    offset: Annotated[int, Query(ge=0, description="Скільки записів пропустити")] = 0,
):
    """Повернути записи за фільтрами (через AND), відсортовані за id"""
    return repository.list_records(category_id, status, min_value, q, limit, offset)


@router.get(
    "/{record_id}",
    response_model=RecordRead,
    summary="Один запис",
    responses={404: {"description": "Запис не знайдено"}},
)
def get_record(
    record_id: Annotated[int, Path(gt=0, description="Ідентифікатор запису")],
):
    """Повернути запис за id"""
    try:
        return repository.get_record(record_id)
    except repository.NotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from None


@router.post(
    "",
    response_model=RecordRead,
    status_code=201,
    summary="Створити запис",
    responses={
        404: {"description": "Категорію не знайдено"},
        409: {"description": "Запис з таким code вже існує"},
    },
)
def create_record(record: RecordCreate):
    """Створити новий запис"""
    try:
        return repository.create_record(record.model_dump())
    except repository.NotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from None
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409, detail="Запис з таким code вже існує"
        ) from None


@router.put(
    "/{record_id}",
    response_model=RecordRead,
    summary="Замінити запис",
    responses={
        404: {"description": "Запис або категорію не знайдено"},
        409: {"description": "Запис з таким code вже існує"},
    },
)
def replace_record(
    record: RecordReplace,
    record_id: Annotated[int, Path(gt=0, description="Ідентифікатор запису")],
):
    """Повністю замінити змінювані поля запису"""
    try:
        return repository.replace_record(record_id, record.model_dump())
    except repository.NotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from None
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409, detail="Запис з таким code вже існує"
        ) from None


@router.delete(
    "/{record_id}",
    status_code=204,
    summary="Видалити запис",
    responses={404: {"description": "Запис не знайдено"}},
)
def delete_record(
    record_id: Annotated[int, Path(gt=0, description="Ідентифікатор запису")],
):
    """Видалити запис за id"""
    try:
        repository.delete_record(record_id)
    except repository.NotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from None


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=201,
    summary="Створити кілька записів (пакет)",
    responses={
        404: {"description": "Категорію не знайдено, жоден запис не збережено"},
        409: {"description": "Дублікат code, жоден запис не збережено"},
    },
)
def create_records_bulk(records: RecordBatch):
    """Створити всі записи пакета однією транзакцією"""
    try:
        return repository.create_records_bulk([item.model_dump() for item in records])
    except repository.NotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from None
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409, detail="Дублікат code, жоден запис не збережено"
        ) from None
