from typing import List, Dict, Optional
from collections import defaultdict
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton

from config import CONFIGS_PER_PAGE


def build_country_keyboard(
    proxies: List[Dict],
    user_id: int,
    sub_id: str
) -> InlineKeyboardMarkup:
    """Строит клавиатуру со странами."""
    groups = defaultdict(list)
    for p in proxies:
        groups[p["country"]].append(p)
    
    buttons = []
    for country, items in sorted(groups.items(), key=lambda x: -len(x[1])):
        proto_counts = defaultdict(int)
        for p in items:
            proto_counts[p["proto"]] += 1
        
        proto_str = " | ".join([f"{k}:{v}" for k, v in proto_counts.items()])
        label = f"{country} ({len(items)}) [{proto_str}]"
        
        buttons.append([
            InlineKeyboardButton(
                text=label,
                callback_data=f"country_{user_id}_{sub_id}_{country}"
            )
        ])
    
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def build_proto_keyboard(
    proxies: List[Dict],
    user_id: int,
    sub_id: str,
    country: str
) -> InlineKeyboardMarkup:
    """Строит клавиатуру с протоколами для выбранной страны."""
    groups = defaultdict(list)
    for p in proxies:
        if p["country"] == country:
            groups[p["proto"]].append(p)
    
    buttons = []
    for proto, items in sorted(groups.items(), key=lambda x: -len(x[1])):
        buttons.append([
            InlineKeyboardButton(
                text=f"{proto} ({len(items)})",
                callback_data=f"proto_{user_id}_{sub_id}_{country}_{proto}"
            )
        ])
    
    buttons.append([
        InlineKeyboardButton(
            text="◀ Назад к странам",
            callback_data=f"back_country_{user_id}_{sub_id}"
        )
    ])
    
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def build_config_keyboard(
    proxies: List[Dict],
    user_id: int,
    sub_id: str,
    country: str,
    proto: str,
    page: int = 0,
    fav_indices: Optional[List[int]] = None
) -> InlineKeyboardMarkup:
    """Строит клавиатуру с конфигами и пагинацией."""
    if fav_indices is None:
        fav_indices = []
    
    filtered = [p for p in proxies if p["country"] == country and p["proto"] == proto]
    total = len(filtered)
    
    if total == 0:
        return InlineKeyboardMarkup(inline_keyboard=[])
    
    total_pages = max(1, (total + CONFIGS_PER_PAGE - 1) // CONFIGS_PER_PAGE)
    page = max(0, min(page, total_pages - 1))
    
    start = page * CONFIGS_PER_PAGE
    end = min(start + CONFIGS_PER_PAGE, total)
    
    buttons = []
    for idx, p in enumerate(filtered[start:end]):
        global_idx = proxies.index(p)
        star = "⭐ " if global_idx in fav_indices else ""
        label = f"{star}{p['name'][:25]} ({p['ip']})"
        
        buttons.append([
            InlineKeyboardButton(
                text=label,
                callback_data=f"config_{user_id}_{sub_id}_{global_idx}"
            )
        ])
    
    # Пагинация
    nav = []
    if page > 0:
        nav.append(
            InlineKeyboardButton(
                text="◀",
                callback_data=f"page_{user_id}_{sub_id}_{country}_{proto}_{page-1}"
            )
        )
    
    nav.append(
        InlineKeyboardButton(
            text=f"{page+1}/{total_pages}",
            callback_data="ignore"
        )
    )
    
    if page < total_pages - 1:
        nav.append(
            InlineKeyboardButton(
                text="▶",
                callback_data=f"page_{user_id}_{sub_id}_{country}_{proto}_{page+1}"
            )
        )
    
    if nav:
        buttons.append(nav)
    
    # Управление
    buttons.append([
        InlineKeyboardButton(
            text="⭐ Избранное",
            callback_data=f"fav_list_{user_id}_{sub_id}"
        )
    ])
    
    buttons.append([
        InlineKeyboardButton(
            text="◀ Назад к протоколам",
            callback_data=f"back_proto_{user_id}_{sub_id}_{country}"
        )
    ])
    
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def build_favorites_keyboard(
    proxies: List[Dict],
    user_id: int,
    sub_id: str,
    fav_indices: List[int]
) -> InlineKeyboardMarkup:
    """Строит клавиатуру с избранными конфигами."""
    buttons = []
    
    for idx in fav_indices:
        if idx < len(proxies):
            p = proxies[idx]
            buttons.append([
                InlineKeyboardButton(
                    text=f"⭐ {p['name'][:25]} ({p['ip']})",
                    callback_data=f"config_{user_id}_{sub_id}_{idx}"
                )
            ])
    
    buttons.append([
        InlineKeyboardButton(
            text="◀ Назад",
            callback_data=f"back_country_{user_id}_{sub_id}"
        )
    ])
    
    return InlineKeyboardMarkup(inline_keyboard=buttons)
