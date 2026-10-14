import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import ClassVar

ITERATIONS = 200_000
SESSION_TIMEOUT_SEC = 900
EMAIL_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{2,63}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+")


def now():
    return datetime.now(timezone.utc)


class User:
    def __init__(self, username, email, role, password, active=True):
        self.username = username
        self.email = email
        self.role = role
        self.active = active
        self.set_password(password)

    @property
    def email(self):
        return self._email

    @email.setter
    def email(self, value):
        if not EMAIL_RE.fullmatch(value):
            raise ValueError("Некоректний email: " + value)
        self._email = value

    def _make_hash(self, password):
        salt = self.__password_salt
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)

    def set_password(self, password):
        self.__password_salt = os.urandom(16)
        self.__password_hash = self._make_hash(password)

    def check_password(self, password):
        return hmac.compare_digest(self._make_hash(password), self.__password_hash)

    def deactivate(self):
        self.active = False

    def __str__(self):
        return f"{self.username} ({self.email}, {self.role}, active={self.active})"


class Admin(User):
    def __init__(self, username, email, password):
        super().__init__(username, email, "admin", password)
        self.permissions = set()

    def grant_permission(self, permission):
        self.permissions.add(permission)

    def revoke_permission(self, permission):
        self.permissions.discard(permission)

    def has_permission(self, permission):
        return permission in self.permissions

    def __str__(self):
        return f"{super().__str__()} permissions={sorted(self.permissions)}"


@dataclass
class Session:
    ip: str
    login_time: datetime
    last_activity: datetime

    def touch(self):
        self.last_activity = now()

    def is_active(self, timeout_sec):
        if timeout_sec <= 0:
            raise ValueError("timeout_sec має бути більше 0")
        return now() - self.last_activity <= timedelta(seconds=timeout_sec)


@dataclass
class AuditRecord:
    time: datetime
    username: str
    action: str


class AuditLog:
    def __init__(self):
        self.records = []

    def add_log(self, username, action):
        self.records.append(AuditRecord(now(), username, action))

    def show_all(self):
        for r in self.records:
            print(f"{r.time:%Y-%m-%d %H:%M:%S} UTC  {r.username}  {r.action}")


class UserAccount:
    KEYS: ClassVar[dict] = {"user": User, "session": Session, "audit_log": AuditLog}

    def __init__(self, user, session=None, audit_log=None):
        self.user = user
        self.session = session
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username, password, ip):
        ok = (
            self.user.active
            and username == self.user.username
            and self.user.check_password(password)
        )
        if not ok:
            self.audit_log.add_log(username, "login_failure")
            return False
        self.session = Session(ip, now(), now())
        self.session.touch()
        self.audit_log.add_log(username, "login_success")
        return True

    def is_authenticated(self):
        if self.session is None:
            return False
        return self.session.is_active(SESSION_TIMEOUT_SEC)

    def logout(self):
        self.session = None
        self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key):
        if key not in self.KEYS:
            raise KeyError(key)
        return getattr(self, key)

    def __setitem__(self, key, value):
        if key not in self.KEYS:
            raise KeyError(key)
        if not isinstance(value, self.KEYS[key]):
            raise TypeError("Неправильний тип для " + key)
        setattr(self, key, value)


def run_demo():
    user = User("student01", "student01@example.com", "user", "Pass_123")
    account = UserAccount(user)

    print("1. Вхід")
    print("Невірний пароль:", account.login("student01", "wrong", "10.0.0.1"))
    print("Вірний пароль:", account.login("student01", "Pass_123", "10.0.0.1"))

    print("\n2. Зміна email")
    user.email = "new_mail1@example.com"
    print("Новий email:", user.email)
    try:
        user.email = "bad@mail"
    except ValueError as error:
        print("Помилка:", error)

    print("\n3. Права адміністратора")
    admin = Admin("admin01", "admin01@example.com", "Admin_123")
    admin.grant_permission("read_logs")
    print(admin)
    admin.revoke_permission("read_logs")
    print("Має read_logs:", admin.has_permission("read_logs"))

    print("\n4. Таймаут сеансу")
    print("Зараз автентифікований:", account.is_authenticated())
    account["session"].last_activity -= timedelta(seconds=1000)
    print("Через 1000 с:", account.is_authenticated())

    print("\n5. Вихід")
    account.logout()
    print("Після logout:", account.is_authenticated())

    print("\n6. Журнал аудиту")
    account["audit_log"].show_all()
