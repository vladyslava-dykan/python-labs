# Лабораторна робота №3. Облік часу відновлення сервісів (варіант 8)

Сервіс зберігає навчальні вимірювання часу відновлення сервісів. Категорії: database, web_service, file_storage. Поле value це час відновлення у хвилинах (число, не менше 0). Поріг: 60.0 хв. Усі дані навчальні.

## Встановлення
pip install -r requirements.txt

## Початкове заповнення бази
python -m labs.lab03.seed

## Запуск API
uvicorn labs.lab03.main:app --reload --host 127.0.0.1 --port 8000
Swagger UI: http://127.0.0.1:8000/docs

## Приклади запитів
- GET /ping повертає 200 і {"status": "ok"}
- GET /records?category_id=1&status=new&limit=5&offset=0 повертає відфільтрований список
- POST /records із тілом {"code": "V08-TEST", "title": "Тестове вимірювання", "category_id": 1, "value": 45.5, "status": "new"} повертає 201
- POST /records/bulk із двома записами, де другий має code V08-01, який уже є в базі, повертає 409, і жоден запис пакета не зберігається