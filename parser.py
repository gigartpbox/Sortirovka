import base64
import json
import re
import logging
from typing import Optional, List, Dict, Any
from urllib.parse import parse_qs, urlparse

from utils import extract_country, is_ru_white, safe_json_loads, safe_yaml_loads

logger = logging.getLogger(__name__)


def parse_proxy_line(line: str) -> Optional[Dict[str, Any]]:
    """Парсит одну строку подписки. Поддерживает все популярные протоколы."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # VLESS
    if line.startswith("vless://"):
        return _parse_vless(line)
    
    # VMess
    if line.startswith("vmess://"):
        return _parse_vmess(line)
    
    # Shadowsocks
    if line.startswith("ss://"):
        return _parse_ss(line)
    
    # Trojan
    if line.startswith("trojan://"):
        return _parse_trojan(line)
    
    # TUIC
    if line.startswith("tuic://"):
        return _parse_tuic(line)
    
    # Hysteria / Hysteria2
    if line.startswith("hysteria://") or line.startswith("hysteria2://"):
        return _parse_hysteria(line)
    
    # SOCKS
    if line.startswith("socks://"):
        return _parse_socks(line)
    
    # HTTP
    if line.startswith("http://") and not line.startswith("https://"):
        return _parse_http(line)
    
    # WireGuard
    if line.startswith("wireguard://"):
        return _parse_wireguard(line)
    
    return None


def _parse_vless(line: str) -> Optional[Dict[str, Any]]:
    """Парсит VLESS с полной поддержкой Reality."""
    match = re.match(r'vless://([^@]+)@([^:]+):(\d+)(\?.*)?(#.*)?', line)
    if not match:
        return None
    
    uuid, ip, port, params, name = match.groups()
    params_dict = parse_qs(params[1:]) if params else {}
    
    return {
        "proto": "vless",
        "uuid": uuid,
        "ip": ip,
        "port": int(port),
        "name": name[1:] if name else "vless",
        "country": extract_country(name or ""),
        "raw": line,
        "is_ru_white": is_ru_white(ip),
        "extra": {
            "flow": params_dict.get("flow", [""])[0],
            "fp": params_dict.get("fp", [""])[0],
            "security": params_dict.get("security", [""])[0],
            "sni": params_dict.get("sni", [""])[0],
            "pbk": params_dict.get("pbk", [""])[0],
            "sid": params_dict.get("sid", [""])[0],
            "type": params_dict.get("type", [""])[0],
            "encryption": params_dict.get("encryption", [""])[0],
        }
    }


def _parse_vmess(line: str) -> Optional[Dict[str, Any]]:
    """Парсит VMess (base64 JSON)."""
    try:
        b64 = line[8:]
        # Добавляем паддинг
        if len(b64) % 4:
            b64 += "=" * (4 - len(b64) % 4)
        
        decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
        data = json.loads(decoded)
        
        ip = data.get("add", "unknown")
        return {
            "proto": "vmess",
            "uuid": data.get("id", ""),
            "ip": ip,
            "port": int(data.get("port", 0)),
            "name": data.get("ps", "vmess"),
            "country": extract_country(data.get("ps", "")),
            "raw": line,
            "is_ru_white": is_ru_white(ip),
            "extra": {
                "aid": data.get("aid", 0),
                "net": data.get("net", "tcp"),
                "type": data.get("type", "none"),
                "host": data.get("host", ""),
                "path": data.get("path", ""),
                "tls": data.get("tls", ""),
                "sni": data.get("sni", ""),
                "alpn": data.get("alpn", ""),
                "fp": data.get("fp", ""),
                "security": data.get("security", ""),
            }
        }
    except json.JSONDecodeError as e:
        logger.debug(f"Ошибка парсинга VMess JSON: {e}")
        return None
    except Exception as e:
        logger.error(f"Неизвестная ошибка парсинга VMess: {e}")
        return None


def _parse_ss(line: str) -> Optional[Dict[str, Any]]:
    """Парсит Shadowsocks (SIP002 + legacy)."""
    try:
        raw = line[5:]
        name = "ss"
        if "#" in raw:
            raw, name = raw.split("#", 1)
        
        # SIP002: ss://base64(method:password)@host:port
        if "@" in raw:
            b64_part, host_port = raw.split("@", 1)
            if len(b64_part) % 4:
                b64_part += "=" * (4 - len(b64_part) % 4)
            decoded = base64.b64decode(b64_part).decode('utf-8', errors='ignore')
            
            if ":" not in decoded:
                return None
            method, password = decoded.split(":", 1)
            host, port = host_port.split(":", 1)
        
        # Legacy: ss://base64(method:password@host:port)
        else:
            if len(raw) % 4:
                raw += "=" * (4 - len(raw) % 4)
            decoded = base64.b64decode(raw).decode('utf-8', errors='ignore')
            
            if "@" not in decoded or ":" not in decoded:
                return None
            
            method_pass, host_port = decoded.split("@", 1)
            method, password = method_pass.split(":", 1)
            host, port = host_port.split(":", 1)
        
        return {
            "proto": "ss",
            "ip": host,
            "port": int(port),
            "name": name,
            "country": extract_country(name),
            "raw": line,
            "is_ru_white": is_ru_white(host),
            "extra": {
                "method": method,
                "password": password,
            }
        }
    except (ValueError, IndexError, base64.binascii.Error) as e:
        logger.debug(f"Ошибка парсинга SS: {e}")
        return None
    except Exception as e:
        logger.error(f"Неизвестная ошибка парсинга SS: {e}")
        return None


def _parse_trojan(line: str) -> Optional[Dict[str, Any]]:
    """Парсит Trojan."""
    match = re.match(r'trojan://([^@]+)@([^:]+):(\d+)(\?.*)?(#.*)?', line)
    if not match:
        return None
    
    password, ip, port, params, name = match.groups()
    params_dict = parse_qs(params[1:]) if params else {}
    
    return {
        "proto": "trojan",
        "ip": ip,
        "port": int(port),
        "name": name[1:] if name else "trojan",
        "country": extract_country(name or ""),
        "raw": line,
        "is_ru_white": is_ru_white(ip),
        "extra": {
            "password": password,
            "sni": params_dict.get("sni", [""])[0],
            "fp": params_dict.get("fp", [""])[0],
        }
    }


def _parse_tuic(line: str) -> Optional[Dict[str, Any]]:
    """Парсит TUIC."""
    match = re.match(r'tuic://([^@]+)@([^:]+):(\d+)(\?.*)?(#.*)?', line)
    if not match:
        return None
    
    uuid, ip, port, params, name = match.groups()
    return {
        "proto": "tuic",
        "uuid": uuid,
        "ip": ip,
        "port": int(port),
        "name": name[1:] if name else "tuic",
        "country": extract_country(name or ""),
        "raw": line,
        "is_ru_white": is_ru_white(ip),
        "extra": {}
    }


def _parse_hysteria(line: str) -> Optional[Dict[str, Any]]:
    """Парсит Hysteria и Hysteria2."""
    proto = "hysteria" if line.startswith("hysteria://") else "hysteria2"
    match = re.match(r'hysteria2?://([^:]+):(\d+)(\?.*)?(#.*)?', line)
    if not match:
        return None
    
    ip, port, params, name = match.groups()
    params_dict = parse_qs(params[1:]) if params else {}
    
    return {
        "proto": proto,
        "ip": ip,
        "port": int(port),
        "name": name[1:] if name else proto,
        "country": extract_country(name or ""),
        "raw": line,
        "is_ru_white": is_ru_white(ip),
        "extra": {
            "auth": params_dict.get("auth", [""])[0],
            "obfs": params_dict.get("obfs", [""])[0],
        }
    }


def _parse_socks(line: str) -> Optional[Dict[str, Any]]:
    """Парсит SOCKS5."""
    parsed = urlparse(line)
    return {
        "proto": "socks",
        "ip": parsed.hostname or "unknown",
        "port": parsed.port or 1080,
        "name": parsed.fragment or "socks",
        "country": extract_country(parsed.fragment or ""),
        "raw": line,
        "is_ru_white": is_ru_white(parsed.hostname or ""),
        "extra": {}
    }


def _parse_http(line: str) -> Optional[Dict[str, Any]]:
    """Парсит HTTP прокси."""
    parsed = urlparse(line)
    return {
        "proto": "http",
        "ip": parsed.hostname or "unknown",
        "port": parsed.port or 8080,
        "name": parsed.fragment or "http",
        "country": extract_country(parsed.fragment or ""),
        "raw": line,
        "is_ru_white": is_ru_white(parsed.hostname or ""),
        "extra": {}
    }


def _parse_wireguard(line: str) -> Optional[Dict[str, Any]]:
    """Парсит WireGuard."""
    match = re.match(r'wireguard://([^:]+):(\d+)(#.*)?', line)
    if not match:
        return None
    
    ip, port, name = match.groups()
    return {
        "proto": "wireguard",
        "ip": ip,
        "port": int(port),
        "name": name[1:] if name else "wireguard",
        "country": extract_country(name or ""),
        "raw": line,
        "is_ru_white": is_ru_white(ip),
        "extra": {}
    }


def parse_clash_yaml(content: str) -> List[Dict[str, Any]]:
    """Парсит Clash YAML конфиг."""
    try:
        import yaml
        data = yaml.safe_load(content)
        if not data or "proxies" not in data:
            return []
        
        proxies = []
        for item in data["proxies"]:
            if "name" not in item or "server" not in item:
                continue
            
            name = item.get("name", "clash")
            server = item.get("server", "unknown")
            port = item.get("port", 0)
            proto = item.get("type", "unknown").lower()
            
            proxies.append({
                "proto": proto,
                "ip": server,
                "port": int(port),
                "name": name,
                "country": extract_country(name),
                "raw": json.dumps(item),
                "is_ru_white": is_ru_white(server),
                "extra": {
                    "uuid": item.get("uuid", ""),
                    "cipher": item.get("cipher", ""),
                    "password": item.get("password", ""),
                    "network": item.get("network", ""),
                    "tls": item.get("tls", False),
                    "skip-cert-verify": item.get("skip-cert-verify", False),
                    "udp": item.get("udp", False),
                }
            })
        return proxies
    except ImportError:
        logger.warning("PyYAML не установлен для парсинга Clash")
        return []
    except Exception as e:
        logger.error(f"Ошибка парсинга Clash YAML: {e}")
        return []


def parse_singbox_json(content: str) -> List[Dict[str, Any]]:
    """Парсит Sing-box JSON конфиг."""
    try:
        data = json.loads(content)
        if not data or "outbounds" not in data:
            return []
        
        proxies = []
        for item in data.get("outbounds", []):
            if "type" not in item:
                continue
            
            server = item.get("server", "unknown")
            port = item.get("server_port", 0)
            proto = item.get("type", "unknown").lower()
            name = item.get("tag", f"{proto}_{server}")
            
            proxies.append({
                "proto": proto,
                "ip": server,
                "port": int(port),
                "name": name,
                "country": extract_country(name),
                "raw": json.dumps(item),
                "is_ru_white": is_ru_white(server),
                "extra": {
                    "uuid": item.get("uuid", ""),
                    "password": item.get("password", ""),
                    "cipher": item.get("cipher", ""),
                    "network": item.get("network", ""),
                    "tls": item.get("tls", False),
                }
            })
        return proxies
    except json.JSONDecodeError as e:
        logger.debug(f"Ошибка парсинга Sing-box JSON: {e}")
        return []
    except Exception as e:
        logger.error(f"Ошибка парсинга Sing-box: {e}")
        return []


def parse_xray_json(content: str) -> List[Dict[str, Any]]:
    """Парсит Xray JSON конфиг."""
    try:
        data = json.loads(content)
        proxies = []
        
        # Ищем в outbounds
        outbounds = data.get("outbounds", [])
        if not outbounds:
            return []
        
        for item in outbounds:
            if "protocol" not in item:
                continue
            
            settings = item.get("settings", {})
            vnext = settings.get("vnext", [])
            
            for server in vnext:
                address = server.get("address", "unknown")
                port = server.get("port", 0)
                users = server.get("users", [])
                
                for user in users:
                    name = f"{item.get('tag', 'xray')}_{address}"
                    proxies.append({
                        "proto": item.get("protocol", "unknown"),
                        "ip": address,
                        "port": int(port),
                        "name": name,
                        "country": extract_country(name),
                        "raw": json.dumps(item),
                        "is_ru_white": is_ru_white(address),
                        "extra": {
                            "uuid": user.get("id", ""),
                            "security": user.get("security", ""),
                            "flow": user.get("flow", ""),
                            "encryption": user.get("encryption", ""),
                        }
                    })
        return proxies
    except json.JSONDecodeError as e:
        logger.debug(f"Ошибка парсинга Xray JSON: {e}")
        return []
    except Exception as e:
        logger.error(f"Ошибка парсинга Xray: {e}")
        return []


def parse_subscription(content: str) -> List[Dict[str, Any]]:
    """Парсит подписку с определением формата."""
    content = content.strip()
    if not content:
        return []
    
    # Пробуем парсить как JSON (Sing-box / Xray)
    if content.startswith("{"):
        # Проверяем Sing-box
        proxies = parse_singbox_json(content)
        if proxies:
            return proxies
        
        # Проверяем Xray
        proxies = parse_xray_json(content)
        if proxies:
            return proxies
    
    # Пробуем парсить как YAML (Clash)
    if content.startswith(("proxies:", "mixed-port:", "port:")):
        proxies = parse_clash_yaml(content)
        if proxies:
            return proxies
    
    # Пробуем декодировать base64
    if not content.startswith(("vless://", "vmess://", "ss://", "trojan://", 
                               "hysteria", "tuic://", "socks://", "http://", 
                               "wireguard://")):
        try:
            content = base64.b64decode(content).decode('utf-8', errors='ignore')
        except Exception as e:
            logger.debug(f"Ошибка декодирования base64: {e}")
    
    # Парсим построчно
    proxies = []
    for line in content.split('\n'):
        p = parse_proxy_line(line)
        if p:
            proxies.append(p)
    
    return proxies
