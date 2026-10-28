"""FastAPI - облік часу відновлення сервісів"""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from labs.lab03.config import DOMAIN, THRESHOLD, UNIT
from labs.lab03.database import initialize_database
from labs.lab03.routers import categories, records
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Під час запуску створити відсутні таблиці (дані не змінюються)"""
    initialize_database()
    yield


app = FastAPI(
    title="Облік часу відновлення сервісів",
    description=(
        f"{DOMAIN}. Поле value: час відновлення у хвилинах ({UNIT}) "
        f"Поріг: {THRESHOLD} хв."
    ),
    lifespan=lifespan,
)


@app.get("/ping", summary="Перевірка доступності API")
def ping() -> dict:
    """Повернути статус доступності API"""
    return {"status": "ok"}


@app.get("/student", summary="Дані студента")
def student() -> dict:
    return {
        "student_name": STUDENT_NAME,
        "group_name": GROUP_NAME,
        "variant_number": VARIANT_NUMBER,
    }


app.include_router(categories.router)


app.include_router(records.router)
