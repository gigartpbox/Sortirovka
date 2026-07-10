import asyncio
import logging
from collections import defaultdict
from typing import Optional

from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.fsm.storage.memory import MemoryStorage

from config import TOKEN, CONFIGS_PER_PAGE, MAX_USER_SUBSCRIPTIONS
from downloader import fetch_subscription
from parser import parse_subscription
from keyboards import (
    build_country_keyboard,
    build_proto_keyboard,
    build_config_keyboard,
    build_favorites_keyboard
)
from database import db
from checker import check_all_servers

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Инициализация
bot = Bot(token=TOKEN)
storage = MemoryStorage()
dp = Dispatcher(storage=storage)

# Кеш подписок
subscription_cache: dict = {}


@dp.message(Command("start"))
async def cmd_start(message: Message):
    """Обработчик команды /start."""
    await message.answer(
        "👋 Отправь мне ссылку на подписку.\n\n"
        "Поддерживаются:\n"
        "• V2Ray (VLESS, VMess)\n"
        "• Shadowsocks (SIP002)\n"
        "• Trojan\n"
        "• Hysteria / Hysteria2\n"
        "• TUIC\n"
        "• WireGuard\n"
        "• Clash YAML\n"
        "• Sing-box JSON\n"
        "• Xray JSON\n\n"
        "Команды:\n"
        "/favorites — избранное\n"
        "/check — проверка серверов\n"
        "/list — список подписок"
    )


@dp.message(Command("favorites"))
async def cmd_favorites(message: Message):
    """Обработчик команды /favorites."""
    user_id = message.from_user.id
    subs = db.get_all_subscriptions(user_id)
    
    if not subs:
        await message.answer("❌ Нет подписок. Сначала отправь ссылку.")
        return
    
    sub_id = subs[0]["subscription_id"]
    proxies = db.get_subscription(user_id, sub_id)
    
    if not proxies:
        await message.answer("❌ Подписка не найдена.")
        return
    
    fav_indices = db.get_favorites(user_id)
    fav_proxies = [p for idx, p in enumerate(proxies) if idx in fav_indices]
    
    if not fav_proxies:
        await message.answer("⭐ У тебя пока нет избранных серверов.")
        return
    
    await message.answer(
        f"⭐ Твои избранные серверы ({len(fav_proxies)}):",
        reply_markup=build_favorites_keyboard(proxies, user_id, sub_id, fav_indices)
    )


@dp.message(Command("check"))
async def cmd_check(message: Message):
    """Обработчик команды /check - проверка серверов."""
    user_id = message.from_user.id
    subs = db.get_all_subscriptions(user_id)
    
    if not subs:
        await message.answer("❌ Нет подписок. Сначала отправь ссылку.")
        return
    
    sub_id = subs[0]["subscription_id"]
    proxies = db.get_subscription(user_id, sub_id)
    
    if not proxies:
        await message.answer("❌ Подписка не найдена.")
        return
    
    await message.answer("⏳ Проверяю серверы (первые 10)...")
    
    checked = await check_all_servers(proxies)
    
    online = [p for p in checked if p.get("status") == "online"]
    offline = [p for p in checked if p.get("status") == "offline"]
    
    text = (
        f"📊 Результаты проверки:\n"
        f"✅ Онлайн: {len(online)}\n"
        f"❌ Офлайн: {len(offline)}\n"
        f"❓ Неизвестно: {len(checked) - len(online) - len(offline)}\n\n"
    )
    
    if online:
        text += "🟢 Онлайн (первые 5):\n"
        for p in online[:5]:
            latency = f"{p['latency']:.0f}ms" if p.get("latency") else "N/A"
            text += f"• {p['name'][:20]} — {p['ip']}:{p['port']} — {latency}\n"
    
    await message.answer(text)


@dp.message(Command("list"))
async def cmd_list(message: Message):
    """Обработчик команды /list."""
    user_id = message.from_user.id
    subs = db.get_all_subscriptions(user_id)
    
    if not subs:
        await message.answer("❌ Нет сохранённых подписок.")
        return
    
    text = "📋 Твои подписки:\n\n"
    for s in subs:
        text += f"• {s['subscription_id'][:8]}... — {s['url'][:50]}\n"
    
    await message.answer(text)


@dp.message()
async def handle_subscription(message: Message):
    """Обработчик ссылки на подписку."""
    user_id = message.from_user.id
    url = message.text.strip()
    
    if not url.startswith(("http://", "https://")):
        await message.answer("❌ Это не похоже на ссылку.")
        return
    
    await message.answer("⏳ Загружаю подписку...")
    
    content = await fetch_subscription(url)
    if not content:
        await message.answer("❌ Не удалось скачать подписку. Проверь ссылку.")
        return
    
    proxies = parse_subscription(content)
    if not proxies:
        await message.answer(
            "❌ Не удалось распарсить подписку.\n"
            "Возможные причины:\n"
            "• Неподдерживаемый формат\n"
            "• Испорченные данные\n"
            "• Требуется установка PyYAML (pip install pyyaml)"
        )
        return
    
    # Генерируем ID подписки
    subs = db.get_all_subscriptions(user_id)
    sub_id = f"sub_{user_id}_{len(subs) + 1}"
    
    # Сохраняем в БД
    db.save_subscription(user_id, sub_id, url, proxies)
    db.add_history(user_id, sub_id, url)
    db.delete_old_subscriptions(user_id, MAX_USER_SUBSCRIPTIONS)
    
    # Кешируем
    if user_id not in subscription_cache:
        subscription_cache[user_id] = {}
    subscription_cache[user_id][sub_id] = proxies
    
    # Статистика
    total = len(proxies)
    countries = len(set(p["country"] for p in proxies))
    proto_counts = defaultdict(int)
    for p in proxies:
        proto_counts[p["proto"]] += 1
    proto_str = ", ".join([f"{k}:{v}" for k, v in proto_counts.items()])
    
    await message.answer(
        f"✅ Загружено {total} прокси из {countries} стран.\n"
        f"Протоколы: {proto_str}\n\n"
        "Выбери страну:",
        reply_markup=build_country_keyboard(proxies, user_id, sub_id)
    )


@dp.callback_query()
async def handle_callback(call: CallbackQuery):
    """Обработчик inline-кнопок."""
    data = call.data
    user_id = call.from_user.id
    
    # Игнорируем кнопки-метки
    if data == "ignore":
        await call.answer()
        return
    
    parts = data.split("_")
    if len(parts) < 3:
        await call.answer("❌ Ошибка")
        return
    
    action = parts[0]
    sub_id = parts[2]
    
    # Получаем подписку из кеша или БД
    proxies = subscription_cache.get(user_id, {}).get(sub_id)
    if not proxies:
        proxies = db.get_subscription(user_id, sub_id)
        if proxies:
            if user_id not in subscription_cache:
                subscription_cache[user_id] = {}
            subscription_cache[user_id][sub_id] = proxies
        else:
            await call.answer("❌ Подписка устарела, отправь ссылку заново.")
            await call.message.delete()
            return
    
    try:
        # ===== ОБРАБОТКА ДЕЙСТВИЙ =====
        
        if action == "country":
            _, _, sub_id, country = data.split("_", 3)
            await call.message.edit_text(
                f"🌍 Страна: {country}\nВыбери протокол:",
                reply_markup=build_proto_keyboard(proxies, user_id, sub_id, country)
            )
            await call.answer()
        
        elif action == "back_country":
            _, _, sub_id = data.split("_", 2)
            await call.message.edit_text(
                "Выбери страну:",
                reply_markup=build_country_keyboard(proxies, user_id, sub_id)
            )
            await call.answer()
        
        elif action == "proto":
            _, _, sub_id, country, proto = data.split("_", 4)
            fav = db.get_favorites(user_id)
            await call.message.edit_text(
                f"🔹 {country} → {proto}\nВыбери конфиг:",
                reply_markup=build_config_keyboard(
                    proxies, user_id, sub_id, country, proto, 0, fav
                )
            )
            await call.answer()
        
        elif action == "back_proto":
            _, _, sub_id, country = data.split("_", 3)
            await call.message.edit_text(
                f"🌍 Страна: {country}\nВыбери протокол:",
                reply_markup=build_proto_keyboard(proxies, user_id, sub_id, country)
            )
            await call.answer()
        
        elif action == "page":
            _, _, sub_id, country, proto, page = data.split("_", 5)
            fav = db.get_favorites(user_id)
            await call.message.edit_reply_markup(
                reply_markup=build_config_keyboard(
                    proxies, user_id, sub_id, country, proto, int(page), fav
                )
            )
            await call.answer()
        
        elif action == "config":
            _, _, sub_id, idx = data.split("_", 3)
            idx = int(idx)
            
            if idx >= len(proxies):
                await call.answer("❌ Конфиг не найден")
                return
            
            p = proxies[idx]
            fav_indices = db.get_favorites(user_id)
            is_fav = idx in fav_indices
            
            # Формируем детали
            details = (
                f"📌 {p['name']}\n"
                f"🌐 {p['country']}\n"
                f"📡 {p['proto']}\n"
                f"🔗 {p['ip']}:{p['port']}\n"
            )
            
            if p.get("extra"):
                for k, v in p["extra"].items():
                    if v:
                        details += f"🔧 {k}: {v}\n"
            
            # Кнопки
            kb = InlineKeyboardMarkup(inline_keyboard=[
                [
                    InlineKeyboardButton(
                        text="⭐ Удалить" if is_fav else "⭐ Добавить",
                        callback_data=f"fav_toggle_{user_id}_{sub_id}_{idx}"
                    )
                ],
                [
                    InlineKeyboardButton(
                        text="📋 Копировать",
                        callback_data=f"copy_{user_id}_{sub_id}_{idx}"
                    )
                ],
                [
                    InlineKeyboardButton(
                        text="◀ Назад",
                        callback_data=f"back_proto_{user_id}_{sub_id}_{p['country']}"
                    )
                ]
            ])
            
            await call.message.answer(
                f"{details}\n```\n{p['raw']}\n```",
                parse_mode="Markdown",
                reply_markup=kb
            )
            await call.answer()
        
        elif action == "fav_toggle":
            _, _, _, sub_id, idx = data.split("_", 4)
            idx = int(idx)
            is_fav = db.toggle_favorite(user_id, sub_id, idx)
            await call.answer(f"⭐ {'Добавлено' if is_fav else 'Удалено'} в избранное!")
        
        elif action == "copy":
            _, _, _, sub_id, idx = data.split("_", 4)
            idx = int(idx)
            if idx < len(proxies):
                await call.message.answer(
                    f"```\n{proxies[idx]['raw']}\n```",
                    parse_mode="Markdown"
                )
            await call.answer()
        
        elif action == "fav_list":
            _, _, sub_id = data.split("_", 2)
            fav = db.get_favorites(user_id)
            await call.message.edit_text(
                "⭐ Избранное:",
                reply_markup=build_favorites_keyboard(proxies, user_id, sub_id, fav)
            )
            await call.answer()
        
        else:
            await call.answer("❌ Неизвестное действие")
    
    except Exception as e:
        logger.error(f"Ошибка в callback: {e}", exc_info=True)
        await call.answer("❌ Произошла ошибка")
        try:
            await call.message.edit_text(
                "❌ Произошла ошибка. Попробуй заново."
            )
        except:
            pass


async def main():
    """Запуск бота."""
    logger.info("🚀 Бот запущен!")
    
    # Очистка устаревших данных
    db.cleanup_expired()
    
    try:
        await dp.start_polling(bot)
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}", exc_info=True)
    finally:
        db.close()


if __name__ == "__main__":
    asyncio.run(main())
