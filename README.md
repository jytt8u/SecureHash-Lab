# 🔐 SecureHash-Lab

Учебный CLI-инструмент на Python для работы с паролями.

> ⚠️ **Только для образовательных целей.** Не используйте функцию атаки против систем без разрешения.

---

## Возможности

| Команда    | Описание                                      |
|------------|-----------------------------------------------|
| `hash`     | Хешировать пароль (SHA-256, SHA-512, bcrypt)  |
| `verify`   | Проверить пароль по хешу                      |
| `strength` | Оценить надёжность пароля                     |
| `attack`   | Демонстрация атаки по словарю                 |

---

## Установка

```bash
git clone https://github.com/YOUR_USERNAME/password-tool.git
cd password-tool
pip install -r requirements.txt
```

---

## Использование

### Хеширование

```bash
# SHA-256 с автоматической солью
python password_tool.py hash "MyP@ssw0rd"

# SHA-512 со своей солью
python password_tool.py hash "MyP@ssw0rd" -a sha512 -s mysupersalt

# bcrypt (соль встроена)
python password_tool.py hash "MyP@ssw0rd" -a bcrypt -r 12
```

Вывод (SHA-256):
```
  Алгоритм: sha256
  Соль:     a3f1c8e2...
  Хеш:      7d3b9f...
```

---

### Проверка пароля

```bash
# SHA-256
python password_tool.py verify "MyP@ssw0rd" \
  --hash "7d3b9f..." \
  --salt "a3f1c8e2..." \
  -a sha256

# bcrypt
python password_tool.py verify "MyP@ssw0rd" \
  --hash '$2b$12$...' \
  -a bcrypt
```

---

### Оценка надёжности

```bash
python password_tool.py strength "qwerty123"
python password_tool.py strength "Tr0ub4dor&3"
```

Вывод:
```
────────────────────────────────────────
  Уровень:  Слабый 🟠
  Оценка:   3/10
  Длина:    9 символов
  Энтропия: ~42.6 бит

  Проблемы:
    ⚠  Нет прописных букв
    ⚠  Нет спецсимволов
    ⚠  Обнаружены последовательности
────────────────────────────────────────
```

---

### Атака по словарю (учебная)

```bash
# Сначала хешируем известный пароль
python password_tool.py hash "dragon" -a sha256 -s testsalt

# Затем «атакуем»
python password_tool.py attack \
  --hash "<полученный_хеш>" \
  --salt testsalt \
  -a sha256 \
  -w wordlists/rockyou-top1000.txt
```

Скачать словарь rockyou можно здесь: https://github.com/brannondorsey/naive-hashcat/releases

---

## Структура проекта

```
password-tool/
├── password_tool.py        # Основной CLI-скрипт
├── requirements.txt        # Зависимости
├── wordlists/
│   └── rockyou-top1000.txt # Пример словаря (добавьте сами)
└── README.md
```

---

## Зависимости

```
bcrypt>=4.0.0
```

---

## Как это работает

### Соль
Соль — случайная строка, добавляемая к паролю **до** хеширования.
Это защищает от атак по радужным таблицам (rainbow table attacks).

### SHA-256 / SHA-512
Быстрые криптографические хеши. Подходят как демонстрация, но **не рекомендуются** для хранения паролей в продакшене — слишком быстро перебираются.

### bcrypt
Специально спроектирован для хеширования паролей. Параметр `rounds` управляет «стоимостью» вычисления — чем выше, тем медленнее подбор.

### Атака по словарю
Перебирает пароли из файла и проверяет каждый. Демонстрирует, почему словарные пароли ненадёжны.

---

## Лицензия

MIT
