


import argparse
import hashlib
import hmac
import os
import re
import sys
import time
from pathlib import Path


try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

def generate_salt(length: int = 16) -> str:
    
    return os.urandom(length).hex()


def hash_sha(password: str, salt: str, algorithm: str) -> str:
    salted = (salt + password).encode("utf-8")
    h = hashlib.new(algorithm, salted)
    return h.hexdigest()


def hash_bcrypt(password: str, rounds: int = 12) -> str:
    
    if not BCRYPT_AVAILABLE:
        sys.exit("❌ Установите bcrypt: pip install bcrypt")
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=rounds))
    return hashed.decode("utf-8")


def verify_sha(password: str, salt: str, stored_hash: str, algorithm: str) -> bool:
    computed = hash_sha(password, salt, algorithm)
    return hmac.compare_digest(computed, stored_hash)


def verify_bcrypt(password: str, stored_hash: str) -> bool:
    if not BCRYPT_AVAILABLE:
        sys.exit("❌ Установите bcrypt: pip install bcrypt")
    return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))




def assess_strength(password: str) -> dict:
    score = 0
    issues = []
    tips = []

    length = len(password)
    if length < 8:
        issues.append(f"Слишком короткий ({length} симв.)")
        tips.append("Используйте минимум 12 символов")
    elif length < 12:
        score += 1
        tips.append("Рекомендуется длина ≥ 12 символов")
    elif length < 16:
        score += 2
    else:
        score += 3

    checks = [
        (r"[a-z]", "строчные буквы", 1),
        (r"[A-Z]", "прописные буквы", 1),
        (r"\d",    "цифры",           1),
        (r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>?/\\|`~]", "спецсимволы", 2),
    ]
    for pattern, label, pts in checks:
        if re.search(pattern, password):
            score += pts
        else:
            issues.append(f"Нет: {label}")
            tips.append(f"Добавьте {label}")

    
    common_patterns = [
        (r"(.)\1{2,}", "повторяющиеся символы"),
        (r"(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)", "последовательности"),
        (r"(qwerty|asdf|zxcv|password|пароль|letmein|admin|login)", "словарные слова"),
    ]
    for pattern, label in common_patterns:
        if re.search(pattern, password.lower()):
            score -= 2
            issues.append(f"Обнаружены {label}")
            tips.append(f"Избегайте {label}")

    score = max(0, min(score, 10))

    if score <= 2:
        level, color = "Очень слабый 🔴", "КРИТИЧЕСКИЙ"
    elif score <= 4:
        level, color = "Слабый 🟠", "СЛАБЫЙ"
    elif score <= 6:
        level, color = "Средний 🟡", "СРЕДНИЙ"
    elif score <= 8:
        level, color = "Сильный 🟢", "СИЛЬНЫЙ"
    else:
        level, color = "Очень сильный 💪", "ОТЛИЧНЫЙ"

    
    charset = 0
    if re.search(r"[a-z]", password): charset += 26
    if re.search(r"[A-Z]", password): charset += 26
    if re.search(r"\d",    password): charset += 10
    if re.search(r"[^a-zA-Z0-9]", password): charset += 32
    import math
    entropy = round(length * math.log2(charset), 1) if charset else 0

    return {
        "score": score,
        "level": level,
        "color": color,
        "entropy": entropy,
        "length": length,
        "issues": issues,
        "tips": tips,
    }


def print_strength(result: dict):
    print(f"\n{'─'*40}")
    print(f"  Уровень:  {result['level']}")
    print(f"  Оценка:   {result['score']}/10")
    print(f"  Длина:    {result['length']} символов")
    print(f"  Энтропия: ~{result['entropy']} бит")
    if result["issues"]:
        print(f"\n  Проблемы:")
        for issue in result["issues"]:
            print(f"    ⚠  {issue}")
    if result["tips"]:
        print(f"\n  Советы:")
        for tip in result["tips"]:
            print(f"    →  {tip}")
    print(f"{'─'*40}\n")




DISCLAIMER = """
╔══════════════════════════════════════════════════════════════╗
║  ⚠  ТОЛЬКО ДЛЯ УЧЕБНЫХ ЦЕЛЕЙ                                ║
║  Использование против чужих систем НЕЗАКОННО.               ║
╚══════════════════════════════════════════════════════════════╝
"""

def dictionary_attack(stored_hash: str, salt: str, algorithm: str, wordlist_path: str):
    print(DISCLAIMER)

    path = Path(wordlist_path)
    if not path.exists():
        sys.exit(f"❌ Файл словаря не найден: {wordlist_path}")

    is_bcrypt = stored_hash.startswith("$2")
    total = 0
    found = None
    start = time.perf_counter()

    print(f"  Алгоритм: {'bcrypt' if is_bcrypt else algorithm}")
    print(f"  Хеш:      {stored_hash[:40]}...")
    print(f"  Словарь:  {wordlist_path}\n")

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip()
                if not word:
                    continue
                total += 1

                if total % 5000 == 0:
                    elapsed = time.perf_counter() - start
                    print(f"  Проверено: {total:,} слов ({elapsed:.1f}s)...", end="\r")

                if is_bcrypt:
                    match = verify_bcrypt(word, stored_hash)
                else:
                    match = verify_sha(word, salt, stored_hash, algorithm)

                if match:
                    found = word
                    break

    except KeyboardInterrupt:
        print("\n\n  ⛔ Прервано пользователем.")

    elapsed = time.perf_counter() - start
    print(f"\n  Проверено слов: {total:,}")
    print(f"  Время:          {elapsed:.3f} сек")
    print(f"  Скорость:       {int(total/elapsed):,} хешей/сек\n")

    if found:
        print(f"  ✅ Пароль найден: '{found}'")
        print("  ⚠  Это демонстрирует, почему не стоит использовать словарные пароли!\n")
    else:
        print("  ❌ Пароль не найден в словаре.")
        print("  ✅ Это хороший знак — пароль не является тривиальным.\n")




def cmd_hash(args):
    algorithm = args.algorithm
    password = args.password

    if algorithm == "bcrypt":
        result = hash_bcrypt(password, rounds=args.rounds)
        print(f"\n  Алгоритм: bcrypt (rounds={args.rounds})")
        print(f"  Хеш:      {result}\n")
        print("  ℹ  Соль встроена в bcrypt-хеш, отдельно хранить не нужно.")
    else:
        salt = args.salt if args.salt else generate_salt()
        result = hash_sha(password, salt, algorithm)
        print(f"\n  Алгоритм: {algorithm}")
        print(f"  Соль:     {salt}")
        print(f"  Хеш:      {result}\n")
        print("  ℹ  Сохраните соль вместе с хешем для последующей проверки.")
    print()


def cmd_verify(args):
    algorithm = args.algorithm
    password = args.password
    stored_hash = args.hash

    if algorithm == "bcrypt" or stored_hash.startswith("$2"):
        ok = verify_bcrypt(password, stored_hash)
    else:
        if not args.salt:
            sys.exit("❌ Для SHA укажите --salt")
        ok = verify_sha(password, args.salt, stored_hash, algorithm)

    if ok:
        print("\n  ✅ Пароль верный!\n")
    else:
        print("\n  ❌ Пароль неверный.\n")


def cmd_strength(args):
    result = assess_strength(args.password)
    print_strength(result)


def cmd_attack(args):
    dictionary_attack(args.hash, args.salt or "", args.algorithm, args.wordlist)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="password-tool",
        description="Учебный инструмент для работы с паролями",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── hash ──
    p_hash = sub.add_parser("hash", help="Хешировать пароль")
    p_hash.add_argument("password", help="Пароль для хеширования")
    p_hash.add_argument("-a", "--algorithm", choices=["sha256", "sha512", "bcrypt"],
                        default="sha256", help="Алгоритм (default: sha256)")
    p_hash.add_argument("-s", "--salt", help="Своя соль (SHA only); если не указано — генерируется")
    p_hash.add_argument("-r", "--rounds", type=int, default=12,
                        help="Число раундов bcrypt (default: 12)")
    p_hash.set_defaults(func=cmd_hash)

    # ── verify ──
    p_ver = sub.add_parser("verify", help="Проверить пароль по хешу")
    p_ver.add_argument("password", help="Пароль для проверки")
    p_ver.add_argument("--hash", required=True, help="Сохранённый хеш")
    p_ver.add_argument("-a", "--algorithm", choices=["sha256", "sha512", "bcrypt"],
                       default="sha256")
    p_ver.add_argument("-s", "--salt", help="Соль (для SHA)")
    p_ver.set_defaults(func=cmd_verify)

    # ── strength ──
    p_str = sub.add_parser("strength", help="Оценить надёжность пароля")
    p_str.add_argument("password", help="Пароль для анализа")
    p_str.set_defaults(func=cmd_strength)

    # ── attack ──
    p_atk = sub.add_parser("attack", help="Демонстрация атаки по словарю (учебная)")
    p_atk.add_argument("--hash", required=True, help="Хеш для атаки")
    p_atk.add_argument("-a", "--algorithm", choices=["sha256", "sha512", "bcrypt"],
                       default="sha256")
    p_atk.add_argument("-s", "--salt", default="", help="Соль (для SHA)")
    p_atk.add_argument("-w", "--wordlist", required=True,
                       help="Путь к файлу словаря (по одному слову на строку)")
    p_atk.set_defaults(func=cmd_attack)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
