@echo off
chcp 65001 >nul
title Установка SecureHash-Lab

echo.
echo  ╔══════════════════════════════════════╗
echo  ║     Установка SecureHash-Lab         ║
echo  ╚══════════════════════════════════════╝
echo.

echo  [1/3] Проверка Python...
py --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo  ❌ Python не найден!
    echo.
    echo  Скачай Python с сайта: https://python.org/downloads
    echo  При установке обязательно поставь галочку:
    echo  "Add python.exe to PATH"
    echo.
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('py --version') do set PYVER=%%i
echo  ✅ Найден %PYVER%

echo.
echo  [2/3] Обновление pip...
py -m pip install --upgrade pip --quiet
echo  ✅ pip обновлён

echo.
echo  [3/3] Установка зависимостей...
py -m pip install bcrypt --quiet
if errorlevel 1 (
    echo  ⚠  bcrypt не установился, но инструмент работает без него
) else (
    echo  ✅ bcrypt установлен
)

echo.
echo  ══════════════════════════════════════
echo  ✅ Установка завершена!
echo  ══════════════════════════════════════
echo.
echo  Запуск инструмента...
echo.
timeout /t 2 >nul

py menu.py

pause
