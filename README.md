# Telegram Proxy Bot

Бот для парсинга, сортировки и проверки прокси-подписок.

## Возможности

- **Поддерживаемые протоколы**: VLESS, VMess, Shadowsocks, Trojan, Hysteria, Hysteria2, TUIC, WireGuard, SOCKS, HTTP
- **Форматы подписок**: Base64, Clash YAML, Sing-box JSON, Xray JSON, GitHub Raw
- **Сортировка**: по странам, протоколам, имени, IP
- **Поиск**: по названию и IP
- **Избранное**: сохранение любимых серверов
- **Проверка**: TCP, TLS, задержка
- **Пагинация**: по 10 конфигов на страницу
- **Кеширование**: оптимизация памяти
- **База данных**: SQLite для хранения подписок и истории

## Установка в Termux

```bash
pkg update && pkg upgrade -y
pkg install python python-pip -y
pip install -r requirements.txt
python bot.py
