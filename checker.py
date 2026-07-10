import asyncio
import logging
import ssl
from typing import Optional, Tuple
import socket

import aiohttp
from aiohttp import ClientTimeout, ClientError

from config import CHECKER_TIMEOUT, CHECKER_RETRIES

logger = logging.getLogger(__name__)


async def check_tcp(ip: str, port: int, timeout: int = CHECKER_TIMEOUT) -> bool:
    """Проверяет TCP-доступность сервера."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False
    except Exception as e:
        logger.debug(f"Ошибка TCP-проверки {ip}:{port}: {e}")
        return False


async def check_tls(ip: str, port: int, sni: str = "", timeout: int = CHECKER_TIMEOUT) -> Tuple[bool, Optional[str]]:
    """Проверяет TLS-соединение и возвращает сертификат."""
    if not sni:
        sni = ip
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=context, server_hostname=sni),
            timeout=timeout
        )
        
        ssl_obj = writer.get_extra_info("ssl_object")
        cert = ssl_obj.getpeercert() if ssl_obj else None
        
        writer.close()
        await writer.wait_closed()
        
        return True, cert
    except (asyncio.TimeoutError, ConnectionRefusedError, ssl.SSLError, OSError):
        return False, None
    except Exception as e:
        logger.debug(f"Ошибка TLS-проверки {ip}:{port}: {e}")
        return False, None


async def check_ping(ip: str, port: int, timeout: int = CHECKER_TIMEOUT) -> Optional[float]:
    """Измеряет задержку до сервера (в миллисекундах)."""
    try:
        start = asyncio.get_event_loop().time()
        
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        
        end = asyncio.get_event_loop().time()
        latency = (end - start) * 1000  # в мс
        
        writer.close()
        await writer.wait_closed()
        
        return latency
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None
    except Exception as e:
        logger.debug(f"Ошибка проверки задержки {ip}:{port}: {e}")
        return None


async def check_server(proxy: dict) -> dict:
    """Полная проверка сервера (TCP + TLS + задержка)."""
    ip = proxy.get("ip", "")
    port = proxy.get("port", 0)
    
    if not ip or ip == "unknown" or not port:
        return {**proxy, "status": "unknown", "latency": None}
    
    # Проверка TCP
    tcp_ok = await check_tcp(ip, port)
    if not tcp_ok:
        return {**proxy, "status": "offline", "latency": None}
    
    # Проверка задержки
    latency = await check_ping(ip, port)
    
    # Проверка TLS (если есть sni)
    sni = proxy.get("extra", {}).get("sni", "")
    if sni:
        tls_ok, cert = await check_tls(ip, port, sni)
        return {**proxy, "status": "online", "latency": latency, "tls_ok": tls_ok, "cert": cert}
    
    return {**proxy, "status": "online", "latency": latency}


async def check_all_servers(proxies: list, limit: int = 10) -> list:
    """Проверяет все серверы (ограниченно)."""
    checked = []
    to_check = proxies[:limit]  # Проверяем только первые limit
    
    tasks = [check_server(p) for p in to_check]
    results = await asyncio.gather(*tasks)
    
    checked.extend(results)
    if len(proxies) > limit:
        checked.extend(proxies[limit:])
    
    return checked
