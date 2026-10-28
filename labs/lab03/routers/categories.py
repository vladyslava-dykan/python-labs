"""Маршрути для категорій"""

import sqlite3
from typing import Annotated

from fastapi import APIRouter, HTTPException, Path

from labs.lab03 import repository
from labs.lab03.schemas import CategoryCreate, CategoryRead

router = APIRouter(prefix="/categories", tags=["categories"])


@router.get("", response_model=list[CategoryRead], summary="Список категорій")
def list_categories():
    """Повернути всі категорії за зростанням id"""
    return repository.list_categories()


@router.post(
    "",
    response_model=CategoryRead,
    status_code=201,
    summary="Створити категорію",
    responses={409: {"description": "Категорія з такою назвою вже існує"}},
)
def create_category(category: CategoryCreate):
    """Створити нову категорію"""
    try:
        return repository.create_category(category.name)
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409, detail="Категорія з такою назвою вже існує"
        ) from None


@router.delete(
    "/{category_id}",
    status_code=204,
    summary="Видалити порожню категорію",
    responses={
        404: {"description": "Категорію не знайдено"},
        409: {"description": "Категорія містить записи"},
    },
)
def delete_category(
    category_id: Annotated[int, Path(gt=0, description="Ідентифікатор категорії")],
):
    """Видалити категорію, якщо в ній немає записів"""
    try:
        repository.delete_category(category_id)
    except repository.NotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from None
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409, detail="Категорія містить записи"
        ) from None
