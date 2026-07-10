import re
import ipaddress
import logging
from typing import Optional, List
from config import RU_WHITELIST_NETS

logger = logging.getLogger(__name__)


def extract_country(name: str) -> str:
    """Извлекает страну из имени конфига (по флагу или тексту)."""
    if not name:
        return "XX"
    
    # Поиск флага (эмодзи страны)
    flag_match = re.search(r'([\U0001F1E6-\U0001F1FF]{2})', name)
    if flag_match:
        return flag_match.group(0)
    
    # Поиск по тексту
    country_map = {
        "россия": "🇷🇺", "russia": "🇷🇺", "ru": "🇷🇺",
        "германия": "🇩🇪", "germany": "🇩🇪", "de": "🇩🇪",
        "франция": "🇫🇷", "france": "🇫🇷", "fr": "🇫🇷",
        "нидерланды": "🇳🇱", "netherlands": "🇳🇱", "nl": "🇳🇱",
        "сша": "🇺🇸", "usa": "🇺🇸", "united states": "🇺🇸",
        "великобритания": "🇬🇧", "uk": "🇬🇧", "united kingdom": "🇬🇧",
        "сингапур": "🇸🇬", "singapore": "🇸🇬", "sg": "🇸🇬",
        "япония": "🇯🇵", "japan": "🇯🇵", "jp": "🇯🇵",
        "канада": "🇨🇦", "canada": "🇨🇦", "ca": "🇨🇦",
        "австралия": "🇦🇺", "australia": "🇦🇺", "au": "🇦🇺",
        "индия": "🇮🇳", "india": "🇮🇳", "in": "🇮🇳",
        "бразилия": "🇧🇷", "brazil": "🇧🇷", "br": "🇧🇷",
        "оаэ": "🇦🇪", "uae": "🇦🇪", "united arab emirates": "🇦🇪",
        "эстония": "🇪🇪", "estonia": "🇪🇪", "ee": "🇪🇪",
        "филиппины": "🇵🇭", "philippines": "🇵🇭", "ph": "🇵🇭",
        "гонконг": "🇭🇰", "hong kong": "🇭🇰", "hk": "🇭🇰",
        "турция": "🇹🇷", "turkey": "🇹🇷", "tr": "🇹🇷",
        "украина": "🇺🇦", "ukraine": "🇺🇦", "ua": "🇺🇦",
        "казахстан": "🇰🇿", "kazakhstan": "🇰🇿", "kz": "🇰🇿",
    }
    
    name_lower = name.lower()
    for key, flag in country_map.items():
        if key in name_lower:
            return flag
    
    return "XX"


def is_ru_white(ip: str) -> bool:
    """Проверяет, принадлежит ли IP белому списку РФ."""
    if not ip or ip == "unknown":
        return False
    
    try:
        ip_obj = ipaddress.ip_address(ip)
        for net in RU_WHITELIST_NETS:
            if ip_obj in ipaddress.ip_network(net, strict=False):
                return True
    except ValueError as e:
        logger.debug(f"Невалидный IP для проверки RU-white: {ip} - {e}")
    except Exception as e:
        logger.error(f"Ошибка проверки RU-white: {e}")
    
    return False


def is_blocked_ip(host: str) -> bool:
    """Проверяет, не является ли хост локальным/заблокированным."""
    if not host:
        return True
    
    try:
        ip = ipaddress.ip_address(host)
        from config import BLOCKED_IPS
        for blocked in BLOCKED_IPS:
            if ip in ipaddress.ip_network(blocked, strict=False):
                return True
    except ValueError:
        # Это не IP-адрес, а домен — пропускаем
        pass
    except Exception as e:
        logger.error(f"Ошибка проверки blocked IP: {e}")
    
    return False


def normalize_github_url(url: str) -> str:
    """Преобразует GitHub URL в raw-ссылку."""
    if "github.com" in url and "/blob/" in url:
        return url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
    return url


def safe_json_loads(text: str) -> Optional[dict]:
    """Безопасная загрузка JSON."""
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        logger.debug(f"Ошибка парсинга JSON: {e}")
        return None
    except Exception as e:
        logger.error(f"Неизвестная ошибка парсинга JSON: {e}")
        return None


def safe_yaml_loads(text: str) -> Optional[dict]:
    """Безопасная загрузка YAML."""
    try:
        import yaml
        return yaml.safe_load(text)
    except ImportError:
        logger.warning("PyYAML не установлен. Установите: pip install pyyaml")
        return None
    except Exception as e:
        logger.debug(f"Ошибка парсинга YAML: {e}")
        return None
