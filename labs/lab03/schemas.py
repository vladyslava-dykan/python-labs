"""Pydantic-моделі запитів і відповідей"""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from labs.lab03.config import VALUE_MIN


class CategoryCreate(BaseModel):
    """Дані для створення категорії"""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    name: str = Field(min_length=2, max_length=40)


class CategoryRead(CategoryCreate):
    """Категорія у відповіді"""

    id: int


class RecordCreate(BaseModel):
    """Дані для створення запису (id задає база)"""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    code: str = Field(min_length=3, max_length=40)
    title: str = Field(min_length=3, max_length=120)
    category_id: int = Field(gt=0)
    value: float = Field(
        ge=VALUE_MIN, allow_inf_nan=False, description="Час відновлення, хвилини"
    )
    status: Literal["new", "in_progress", "done"]


class RecordReplace(RecordCreate):
    """Повна заміна запису, усі змінювані поля обов'язкові"""


class RecordRead(RecordCreate):
    """Запис у відповіді, з id та назвою категорії"""

    id: int
    category_name: str


RecordBatch = Annotated[list[RecordCreate], Field(min_length=1, max_length=100)]
