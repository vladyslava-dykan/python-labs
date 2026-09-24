import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone


def _add_project_root_to_path():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    while True:
        if os.path.isdir(os.path.join(current_dir, 'shared')):
            sys.path.append(current_dir)
            return
        parent_dir = os.path.dirname(current_dir)
        if parent_dir == current_dir:
            return RuntimeError('Не вдалося знайти папку shared/')
        current_dir = parent_dir

_add_project_root_to_path()

from shared.student import VARIANT_NUMBER

SALT = str(VARIANT_NUMBER).zfill(5) 
MIN_LENGTH = 11
HASH_ALGO = 'sha256'

class ValidationError(Exception):
    pass

def generate_hash(password: str, salt: str = SALT) -> str:
    if not password or not salt:
        raise ValueError('Пароль або сіль порожні')
    if len(password) < MIN_LENGTH:
        raise ValidationError('Пароль занадто короткий')
    
    data = (password + salt).encode('utf-8')
    return hashlib.new(HASH_ALGO, data).hexdigest()

def log_event(func):
    def wrapper(*args, **kwargs):
        status = 'failure'
        try:
            res = func(*args, **kwargs)
            if res:
                status = 'success'
            return res
        except Exception:
            status = 'failure'
            raise
        finally:
            log_data = {
                'event': 'login',
                'user': args[0] if args else kwargs.get('username', ''),
                'result': status,
                'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
                'args': list(args),
                'kwargs': kwargs,
            }
            try:
                os.makedirs('labs/lab01/data', exist_ok=True)
                path = 'labs/lab01/data/log.json'
                logs = []
                if os.path.exists(path):
                    with open(path, 'r', encoding='utf-8') as f:
                        logs = json.load(f)
                logs.append(log_data)
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(logs, f, ensure_ascii=False, indent=4)
            except (PermissionError, OSError):
                pass
    return wrapper

def create_user(username, password):
    try:
        return (username, generate_hash(password, SALT))
    except (ValueError, ValidationError):
        return None

def create_users(users_list):
    try:
        os.makedirs('labs/lab01/data', exist_ok=True)
        with open('labs/lab01/data/users.csv', 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['username', 'password_hash'])
            for uname, pwd in users_list:
                data = create_user(uname, pwd)
                if data:
                    writer.writerow(data)
    except (FileNotFoundError, PermissionError, OSError):
        pass

def read_users_db():
    users_db = []
    try:
        with open('labs/lab01/data/users.csv', 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader, None)
            for row in reader:
                if row:
                    users_db.append({'username': row[0], 'hash': row[1]})
                    
        print(f"{'Логін':<20}{'Хеш пароля'}")
        for u in users_db:
            print(f"{u['username']:<20}{u['hash']}")
    except (FileNotFoundError, PermissionError, OSError):
        pass
    return users_db

@log_event
def login(username: str, password: str) -> bool:
    if not username or not password:
        raise ValueError('Порожній логін або пароль')
        
    try:
        db = read_users_db()
        hsh = generate_hash(password, SALT)
        for u in db:
            if u['username'] == username and u['hash'] == hsh:
                return True
        return False
    except (FileNotFoundError, PermissionError, ValidationError, OSError):
        return False

def main():
    users_to_register = (
        ("admin_sec", "SecurePassword#2026"),
        ("crypto_ivan", "StrongCrypto99!"),
        ("guest_user", "weak"),
        ("analyst_olga", "DataScience#88"),
        ("sec_expert", "CyberGuard*555"),
        ("test_user_1", "Short1!"),
        ("auditor_petro", "AuditTrail$777"),
        ("dev_oleh", "PythonCode#1234"),
        ("net_admin", "RouterSwitch#00"),
        ("user_empty", "")
    )

    create_users(users_to_register)
    print("БАЗА ДАНИХ (CSV):")
    read_users_db()
    
    print("\nПЕРЕВІРКА ВХОДУ:")
    print("admin_sec:", login("admin_sec", "SecurePassword#2026"))
    print("crypto_ivan (невірний пароль):", login("crypto_ivan", "wrong"))

if __name__ == '__main__':
    main()