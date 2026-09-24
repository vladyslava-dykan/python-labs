import os
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

users = {
    "crypto_specialist": {"role": "cryptographer", "clearance": 4, "department": "Cryptography", "active": True},
    "privacy_officer": {"role": "privacy_analyst", "clearance": 3, "department": "Privacy", "active": True},
    "data_scientist": {"role": "data_analyst", "clearance": 2, "department": "Analytics", "active": True},
    "field_engineer": {"role": "field_support", "clearance": 2, "department": "Field Ops", "active": True},
    "test_account": {"role": "testing", "clearance": 1, "department": "QA", "active": False}
}

resources = [
    ("encryption_keys", 4), ("privacy_policies", 3), 
    ("anonymized_data", 2), ("field_reports", 2), ("crypto_algorithms", 4), 
    ("consent_forms", 1), ("data_classification", 3), ("key_management", 4), 
    ("statistical_models", 2), ("public_datasets", 1)
]

security_levels = ("Unclassified", "For Official Use", "Confidential", "Secret")
blocked_users = {"test_account", "gdpr_violation", "data_breach_user"}

def display_resources():
    print("РЕСУРСИ СИСТЕМИ:")
    for res_name, level_num in resources:
        level_name = security_levels[level_num - 1]
        print(f"Ресурс: {res_name} | Рівень: {level_name}")

def verify_all_accesses():
    print("\nРЕЗУЛЬТАТИ ПЕРЕВІРКИ:")
    all_users = set(list(users.keys()) + list(blocked_users))

    for username in sorted(all_users):
        for res_name, res_level in resources:
            if username not in users:
                result = "DENY (User not found)"
            elif username in blocked_users:
                result = "DENY (User is blocked)"
            elif not users[username]["active"]:
                result = "DENY (Account inactive)"
            elif users[username]["clearance"] >= res_level:
                result = "ALLOW"
            else:
                result = "DENY (Insufficient clearance)"
            
            print(f"user={username} resource={res_name} -> {result}")

def main():
    display_resources()
    verify_all_accesses()
    

if __name__ == '__main__':
    main()
