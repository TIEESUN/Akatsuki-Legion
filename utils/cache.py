"""
Caching utilities for reducing API calls
"""

import json
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

CACHE_DIR = Path("data/cache")
CACHE_DIR.mkdir(parents=True, exist_ok=True)


class QueryCache:
    """Simple file-based cache for API responses"""
    
    def __init__(self, ttl_seconds: int = 3600):
        """
        Initialize cache
        
        Args:
            ttl_seconds: Time to live for cached entries (default 1 hour)
        """
        self.ttl = ttl_seconds
        self.cache_dir = CACHE_DIR
    
    @staticmethod
    def _get_cache_key(observable: str, source: str) -> str:
        """Generate cache key from observable and source"""
        key_string = f"{observable}:{source}"
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def _get_cache_file(self, observable: str, source: str) -> Path:
        """Get cache file path"""
        key = self._get_cache_key(observable, source)
        return self.cache_dir / f"{key}.json"
    
    def get(self, observable: str, source: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached result
        
        Args:
            observable: IP, domain, URL, or hash
            source: Intelligence source name
            
        Returns:
            Cached result or None if expired/not found
        """
        cache_file = self._get_cache_file(observable, source)
        
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file, "r") as f:
                cached_data = json.load(f)
            
            # Check if expired
            cached_time = datetime.fromisoformat(cached_data.get("timestamp", ""))
            if datetime.now() - cached_time > timedelta(seconds=self.ttl):
                logger.info(f"Cache expired for {observable} from {source}")
                cache_file.unlink()  # Delete expired cache
                return None
            
            logger.info(f"Cache hit for {observable} from {source}")
            return cached_data.get("data")
        
        except Exception as e:
            logger.error(f"Error reading cache: {e}")
            return None
    
    def set(self, observable: str, source: str, data: Dict[str, Any]) -> bool:
        """
        Cache result
        
        Args:
            observable: IP, domain, URL, or hash
            source: Intelligence source name
            data: Result data to cache
            
        Returns:
            True if successful
        """
        cache_file = self._get_cache_file(observable, source)
        
        try:
            cache_data = {
                "timestamp": datetime.now().isoformat(),
                "observable": observable,
                "source": source,
                "data": data,
            }
            
            with open(cache_file, "w") as f:
                json.dump(cache_data, f, indent=2, default=str)
            
            logger.info(f"Cached result for {observable} from {source}")
            return True
        
        except Exception as e:
            logger.error(f"Error writing cache: {e}")
            return False
    
    def clear_all(self) -> int:
        """
        Clear all cache files
        
        Returns:
            Number of files deleted
        """
        count = 0
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                cache_file.unlink()
                count += 1
            except Exception as e:
                logger.error(f"Error deleting cache file: {e}")
        
        logger.info(f"Cleared {count} cache files")
        return count
    
    def clear_expired(self) -> int:
        """
        Clear expired cache entries
        
        Returns:
            Number of files deleted
        """
        count = 0
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                with open(cache_file, "r") as f:
                    cached_data = json.load(f)
                
                cached_time = datetime.fromisoformat(cached_data.get("timestamp", ""))
                if datetime.now() - cached_time > timedelta(seconds=self.ttl):
                    cache_file.unlink()
                    count += 1
            except Exception as e:
                logger.error(f"Error checking cache file: {e}")
        
        logger.info(f"Cleared {count} expired cache files")
        return count
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_files = len(list(self.cache_dir.glob("*.json")))
        
        total_size = sum(f.stat().st_size for f in self.cache_dir.glob("*.json"))
        total_size_mb = total_size / (1024 * 1024)
        
        return {
            "total_entries": total_files,
            "total_size_mb": round(total_size_mb, 2),
            "ttl_seconds": self.ttl,
        }


# Global cache instance
_cache_instance = None


def get_cache(ttl_seconds: int = 3600) -> QueryCache:
    """Get or create cache instance"""
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = QueryCache(ttl_seconds)
    return _cache_instance
