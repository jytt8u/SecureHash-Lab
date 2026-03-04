import os
import sys
import time


from password_tool import (
    hash_sha, hash_bcrypt, verify_sha, verify_bcrypt,
    assess_strength, print_strength, dictionary_attack,
    generate_salt, BCRYPT_AVAILABLE
)

def cls():
    os.system("cls" if os.name == "nt" else "clear")
BANNER = r"""
  ____                            _   _   _           _
 / ___|  ___  ___ _   _ _ __ ___| | | | | | __ _ ___| |__
 \___ \ / _ \/ __| | | | '__/ _ \ | | |_| |/ _` / __| '_ \\
  ___) |  __/ (__| |_| | | |  __/ | |  _  | (_| \__ \ | | |
 |____/ \___|\___|\__,_|_|  \___|_| |_| |_|\__,_|___/_| |_|

         Учебный инструмент по безопасности паролей
"""

def print_banner():
    print(BANNER)
    print("  " + "─" * 54)



MENU = """
  [1]  Хешировать пароль
  [2]  Проверить пароль по хешу
  [3]  Оценить надёжность пароля
  [4]  Атака по словарю (учебная)
  [0]  Выход
"""

def print_menu():
    cls()
    print_banner()
    print(MENU)

def ask(prompt: str, secret: bool = False) -> str:
    if secret:
        import getpass
        return getpass.getpass(f"  {prompt}: ")
    return input(f"  {prompt}: ").strip()

def pause():
    input("\n  Нажмите Enter чтобы вернуться в меню...")

def choose_algorithm() -> str:
    print("\n  Алгоритм:")
    print("    [1] SHA-256")
    print("    [2] SHA-512")
    if BCRYPT_AVAILABLE:
        print("    [3] bcrypt")
    choice = ask("Выбор (по умолчанию 1)")
    mapping = {"1": "sha256", "2": "sha512", "3": "bcrypt", "": "sha256"}
    return mapping.get(choice, "sha256")



def menu_hash():
    cls()
    print("\n  ══════════════════════════════════")
    print("        ХЕШИРОВАНИЕ ПАРОЛЯ")
    print("  ══════════════════════════════════\n")

    password = ask("Введите пароль", secret=True)
    if not password:
        print("\n  ⚠  Пароль не может быть пустым.")
        pause()
        return


    print("\n  Анализ надёжности вашего пароля:")
    result = assess_strength(password)
    print_strength(result)

    algorithm = choose_algorithm()

    print("\n  Хешируем", end="")
    for _ in range(3):
        time.sleep(0.3)
        print(".", end="", flush=True)
    print()

    if algorithm == "bcrypt":
        hashed = hash_bcrypt(password)
        print(f"\n  Алгоритм : bcrypt")
        print(f"  Хеш      : {hashed}")
        print("\n  ℹ  Соль встроена в bcrypt-хеш — храните только хеш.")
    else:
        salt = generate_salt()
        hashed = hash_sha(password, salt, algorithm)
        print(f"\n  Алгоритм : {algorithm}")
        print(f"  Соль     : {salt}")
        print(f"  Хеш      : {hashed}")
        print("\n  ℹ  Сохраните соль и хеш вместе — без соли не проверить пароль!")

    pause()


def menu_verify():
    cls()
    print("\n  ══════════════════════════════════")
    print("        ПРОВЕРКА ПАРОЛЯ")
    print("  ══════════════════════════════════\n")

    password = ask("Введите пароль для проверки", secret=True)
    stored_hash = ask("Вставьте сохранённый хеш")

    is_bcrypt = stored_hash.startswith("$2")

    if is_bcrypt:
        algorithm = "bcrypt"
        salt = ""
    else:
        algorithm = choose_algorithm()
        salt = ask("Введите соль")

    print("\n  Проверяем", end="")
    for _ in range(3):
        time.sleep(0.3)
        print(".", end="", flush=True)
    print()

    if is_bcrypt or algorithm == "bcrypt":
        ok = verify_bcrypt(password, stored_hash)
    else:
        ok = verify_sha(password, salt, stored_hash, algorithm)

    if ok:
        print("\n  Пароль ВЕРНЫЙ!\n")
    else:
        print("\n   Пароль НЕВЕРНЫЙ.\n")

    pause()


def menu_strength():
    cls()
    print("\n  ══════════════════════════════════")
    print("        АНАЛИЗ НАДЁЖНОСТИ")
    print("  ══════════════════════════════════\n")

    password = ask("Введите пароль для анализа", secret=True)
    if not password:
        print("\n  ⚠  Пароль не может быть пустым.")
        pause()
        return

    result = assess_strength(password)
    print_strength(result)


    if result["score"] < 6:
        print("   Пример сильного пароля: Tr0ub4dor&3xZ!")
        print("    (не используйте именно этот — он уже известен)\n")

    pause()


def menu_attack():
    cls()
    print("\n  ══════════════════════════════════")
    print("     АТАКА ПО СЛОВАРЮ (учебная)")
    print("  ══════════════════════════════════")
    print("""
  ⚠  Только для образовательных целей!
     Использование против чужих систем незаконно.
""")

    stored_hash = ask("Вставьте хеш для атаки")
    is_bcrypt = stored_hash.startswith("$2")

    if is_bcrypt:
        algorithm = "bcrypt"
        salt = ""
    else:
        algorithm = choose_algorithm()
        salt = ask("Введите соль (если есть, иначе Enter)")

    wordlist = ask("Путь к файлу словаря (Enter = wordlists/sample.txt)")
    if not wordlist:
        wordlist = "wordlists/sample.txt"

    print()
    dictionary_attack(stored_hash, salt, algorithm, wordlist)
    pause()




def main():
    while True:
        print_menu()
        choice = input("  Ваш выбор: ").strip()

        if choice == "1":
            menu_hash()
        elif choice == "2":
            menu_verify()
        elif choice == "3":
            menu_strength()
        elif choice == "4":
            menu_attack()
        elif choice == "0":
            cls()
            print("\n  До свидания! 👋\n")
            sys.exit(0)
        else:
            print("\n  ⚠  Неверный выбор, попробуйте снова.")
            time.sleep(1)


if __name__ == "__main__":
    main()
