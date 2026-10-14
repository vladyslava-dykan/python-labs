Варіант 8: Фільтр та аналізатор журналів DNS-запитів.


З кореня репозиторію, в активованому віртуальному середовищі:

```
pip install -r requirements.txt
```


```
labs/lab02/
├── __init__.py
├── main.py       # команди demo та analyze
├── task1.py      # класи User, Admin, Session, AuditLog, UserAccount
├── task2.py      # аналізатор DNS-журналу
├── README.md
└── data/
    └── data_v08/
        ├── dns_queries.csv   # журнал DNS (Timestamp, ClientIP, Domain, QueryType)
        └── blacklist.txt     # чорний список, один домен на рядок
```

Усі команди виконуються з кореня репозиторію.

Завдання 1 (демонстрація класів):

```
python -m labs.lab02.main demo
```

Завдання 2 (аналіз DNS-журналу):

```
python -m labs.lab02.main analyze --dns-log labs/lab02/data/data_v08/dns_queries.csv --blacklist labs/lab02/data/data_v08/blacklist.txt --out-csv labs/lab02/data/dns_alerts.csv
```

| Параметр | Опис |
|---|---|
| `--dns-log` | шлях до CSV-журналу DNS (обов'язковий) |
| `--blacklist` | шлях до чорного списку доменів (обов'язковий) |
| `--out-csv` | шлях до CSV зі знайденими аномаліями |
| `--min-domain-len` | довжина домену, починаючи з якої він вважається аномально довгим (за замовчуванням 50) |

- домени з чорного списку (разом з їхніми піддоменами);
- надто довгі частини домену (25 і більше символів поспіль);
- підозрілі TLD: xyz, top, zip, tk, click;
- аномально довгі домени (від `--min-domain-len`);
- статистику запитів за типами A, AAAA, TXT, MX.

- Якщо файл не знайдено, виводиться повідомлення `[ERROR]` і програма завершується з кодом 1.
- Якщо не вказано `--dns-log` або `--blacklist`, `argparse` показує підказку про використання.
- Рядки журналу з некоректною датою чи без потрібних полів пропускаються з попередженням у лозі.