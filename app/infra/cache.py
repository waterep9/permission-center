"""进程内 LRU 缓存，用于缓存权限决策结果。

设计要点：
- 决策结果带有「版本号」，权限模型任何变更都会 bump 全局版本，
  旧版本的缓存条目视为失效，避免脏读。
- 使用 OrderedDict 实现简单 LRU，容量受限防止内存膨胀。
"""
from collections import OrderedDict
from threading import RLock


class DecisionCache:
    def __init__(self, capacity: int = 4096, enabled: bool = True):
        self._capacity = capacity
        self._enabled = enabled
        self._lock = RLock()
        self._store: OrderedDict = OrderedDict()

    def get(self, key: str, version: int):
        if not self._enabled:
            return None
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            if entry["version"] != version:
                del self._store[key]
                return None
            # LRU 重排
            self._store.move_to_end(key)
            return entry["value"]

    def put(self, key: str, version: int, value):
        if not self._enabled:
            return
        with self._lock:
            self._store[key] = {"version": version, "value": value}
            self._store.move_to_end(key)
            while len(self._store) > self._capacity:
                self._store.popitem(last=False)

    def invalidate(self):
        with self._lock:
            self._store.clear()


decision_cache = DecisionCache()
