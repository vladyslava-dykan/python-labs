import os
import random
import sys


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



def evaluate_password(password, all_passwords, criteria, forbidden):
    min_length = criteria['min_length']
    has_digit = any(c.isdigit() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_special = any(not c.isalnum() for c in password)
    length_ok = len(password) >= min_length

    if password in forbidden or not length_ok:
        return 'Заборонений'

    required = [has_digit, has_upper, has_special]
    satisfied = sum(required)

    if satisfied == len(required):
        if len(password) >= min_length + 4:
            is_unique = all_passwords.count(password) == 1
            return 'Дуже сильний' if is_unique else 'Сильний'
        return 'Сильний'

    if 0 < satisfied < len(required):
        return 'Середній'

    if has_digit or has_upper or has_lower or has_special:
        return 'Слабкий'

    return 'Слабкий'

def main():

    passwords = [
        'ThreatH@nt3r', 'weak123', 'P3n3trat10n@Test', 'visitor',
        'Cyber@Defense2023', 'normal', 'Incident@R3sp0nse', 'standard',
        'Risk@Analys1s', 'typical',
    ]
    criteria = {
        'min_length': 10,
        'require_digits': True,
        'require_upper': True,
        'require_special': True,
    }
    forbidden_passwords = {
        'weak123', 'visitor', 'normal', 'standard', 'typical', 'admin',
    }

    duplicate_indices = [
        random.randint(0, len(passwords) - 1) for _ in range(3)
    ]
    passwords.extend(passwords[i] for i in duplicate_indices)

    print('Індекси дублювання:', duplicate_indices, '\n')

    print(f"{'Пароль':<20}{'Довжина':<10}{'Рівень надійності'}")

    for pw in passwords:
        level = evaluate_password(
            pw, passwords, criteria, forbidden_passwords
        )
        print(f'{pw:<20}{len(pw):<10}{level}')

if __name__ == '__main__':
    main()