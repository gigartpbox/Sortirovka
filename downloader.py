import asyncio
import logging
from typing import Optional
from urllib.parse import urlparse

import aiohttp
from aiohttp import ClientTimeout, ClientError

from config import (
    DOWNLOAD_TIMEOUT, MAX_SUBSCRIPTION_SIZE_MB,
    ALLOWED_CONTENT_TYPES
)
from utils import is_blocked_ip, normalize_github_url

logger = logging.getLogger(__name__)


async def fetch_subscription(url: str, retries: int = 2) -> Optional[str]:
    """Скачивает подписку с проверкой безопасности и лимитов."""
    if not url.startswith(("http://", "https://")):
        logger.warning(f"Неверный протокол URL: {url}")
        return None
    
    # Нормализуем GitHub URL
    url = normalize_github_url(url)
    
    # Проверяем хост
    parsed = urlparse(url)
    if is_blocked_ip(parsed.hostname or ""):
        logger.warning(f"Заблокированный хост: {parsed.hostname}")
        return None
    
    timeout = ClientTimeout(total=DOWNLOAD_TIMEOUT)
    max_size_bytes = MAX_SUBSCRIPTION_SIZE_MB * 1024 * 1024
    
    for attempt in range(retries + 1):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=timeout, allow_redirects=True) as response:
                    if response.status != 200:
                        logger.warning(f"HTTP {response.status} для {url}")
                        continue
                    
                    # Проверяем размер
                    content_length = response.headers.get("Content-Length")
                    if content_length and int(content_length) > max_size_bytes:
                        logger.warning(f"Подписка слишком большая: {content_length} байт")
                        return None
                    
                    # Проверяем Content-Type
                    content_type = response.headers.get("Content-Type", "")
                    is_allowed = any(
                        allowed_type in content_type 
                        for allowed_type in ALLOWED_CONTENT_TYPES
                    )
                    if not is_allowed and content_type:
                        logger.debug(f"Неизвестный Content-Type: {content_type}")
                    
                    # Читаем с ограничением
                    data = await response.text()
                    
                    if len(data) > max_size_bytes:
                        logger.warning(f"Подписка слишком большая: {len(data)} байт")
                        return None
                    
                    return data
                    
        except (ClientError, asyncio.TimeoutError) as e:
            logger.warning(f"Ошибка загрузки (попытка {attempt + 1}): {e}")
            if attempt == retries:
                return None
            await asyncio.sleep(1)
        
        except Exception as e:
            logger.error(f"Неизвестная ошибка загрузки: {e}")
            return None
    
    return None
