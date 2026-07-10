import sqlite3
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

from config import DB_PATH, CACHE_TTL_SECONDS

logger = logging.getLogger(__name__)


class Database:
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_tables()
    
    def _init_tables(self):
        """Инициализирует таблицы в БД."""
        cursor = self.conn.cursor()
        
        # Таблица подписок
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS subscriptions (
                user_id INTEGER,
                subscription_id TEXT,
                url TEXT,
                proxies TEXT,
                created_at TIMESTAMP,
                last_used TIMESTAMP,
                PRIMARY KEY (user_id, subscription_id)
            )
        ''')
        
        # Таблица избранного
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS favorites (
                user_id INTEGER,
                subscription_id TEXT,
                proxy_index INTEGER,
                PRIMARY KEY (user_id, subscription_id, proxy_index)
            )
        ''')
        
        # Таблица истории
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS history (
                user_id INTEGER,
                subscription_id TEXT,
                url TEXT,
                loaded_at TIMESTAMP
            )
        ''')
        
        self.conn.commit()
    
    def save_subscription(self, user_id: int, sub_id: str, url: str, proxies: List[Dict]) -> None:
        """Сохраняет подписку в БД."""
        now = datetime.now().isoformat()
        try:
            self.conn.execute(
                'INSERT OR REPLACE INTO subscriptions VALUES (?, ?, ?, ?, ?, ?)',
                (user_id, sub_id, url, json.dumps(proxies), now, now)
            )
            self.conn.commit()
        except Exception as e:
            logger.error(f"Ошибка сохранения подписки: {e}")
    
    def get_subscription(self, user_id: int, sub_id: str) -> Optional[List[Dict]]:
        """Получает подписку из БД."""
        try:
            row = self.conn.execute(
                'SELECT proxies, last_used FROM subscriptions WHERE user_id=? AND subscription_id=?',
                (user_id, sub_id)
            ).fetchone()
            
            if not row:
                return None
            
            # Обновляем время использования
            self.conn.execute(
                'UPDATE subscriptions SET last_used=? WHERE user_id=? AND subscription_id=?',
                (datetime.now().isoformat(), user_id, sub_id)
            )
            self.conn.commit()
            
            return json.loads(row["proxies"])
        except Exception as e:
            logger.error(f"Ошибка получения подписки: {e}")
            return None
    
    def get_all_subscriptions(self, user_id: int) -> List[Dict]:
        """Получает все подписки пользователя."""
        try:
            rows = self.conn.execute(
                'SELECT subscription_id, url, created_at FROM subscriptions WHERE user_id=?',
                (user_id,)
            ).fetchall()
            return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Ошибка получения списка подписок: {e}")
            return []
    
    def delete_old_subscriptions(self, user_id: int, keep: int = 5) -> None:
        """Удаляет старые подписки, оставляя только последние keep штук."""
        try:
            self.conn.execute('''
                DELETE FROM subscriptions 
                WHERE user_id=? AND subscription_id NOT IN (
                    SELECT subscription_id FROM subscriptions
                    WHERE user_id=?
                    ORDER BY last_used DESC
                    LIMIT ?
                )
            ''', (user_id, user_id, keep))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Ошибка удаления старых подписок: {e}")
    
    def toggle_favorite(self, user_id: int, sub_id: str, idx: int) -> bool:
        """Переключает статус избранного."""
        try:
            exists = self.conn.execute(
                'SELECT 1 FROM favorites WHERE user_id=? AND subscription_id=? AND proxy_index=?',
                (user_id, sub_id, idx)
            ).fetchone()
            
            if exists:
                self.conn.execute(
                    'DELETE FROM favorites WHERE user_id=? AND subscription_id=? AND proxy_index=?',
                    (user_id, sub_id, idx)
                )
                self.conn.commit()
                return False
            else:
                self.conn.execute(
                    'INSERT INTO favorites VALUES (?, ?, ?)',
                    (user_id, sub_id, idx)
                )
                self.conn.commit()
                return True
        except Exception as e:
            logger.error(f"Ошибка переключения избранного: {e}")
            return False
    
    def get_favorites(self, user_id: int) -> List[int]:
        """Получает список избранных индексов."""
        try:
            rows = self.conn.execute(
                'SELECT proxy_index FROM favorites WHERE user_id=?',
                (user_id,)
            ).fetchall()
            return [row["proxy_index"] for row in rows]
        except Exception as e:
            logger.error(f"Ошибка получения избранного: {e}")
            return []
    
    def cleanup_expired(self) -> None:
        """Удаляет устаревшие подписки."""
        cutoff = (datetime.now() - timedelta(seconds=CACHE_TTL_SECONDS)).isoformat()
        try:
            deleted = self.conn.execute(
                'DELETE FROM subscriptions WHERE last_used < ?',
                (cutoff,)
            )
            self.conn.commit()
            if deleted.rowcount > 0:
                logger.info(f"Удалено {deleted.rowcount} устаревших подписок")
        except Exception as e:
            logger.error(f"Ошибка очистки устаревших данных: {e}")
    
    def add_history(self, user_id: int, sub_id: str, url: str) -> None:
        """Добавляет запись в историю."""
        try:
            self.conn.execute(
                'INSERT INTO history VALUES (?, ?, ?, ?)',
                (user_id, sub_id, url, datetime.now().isoformat())
            )
            self.conn.commit()
        except Exception as e:
            logger.error(f"Ошибка добавления в историю: {e}")
    
    def close(self) -> None:
        """Закрывает соединение с БД."""
        try:
            self.conn.close()
        except Exception as e:
            logger.error(f"Ошибка закрытия БД: {e}")
