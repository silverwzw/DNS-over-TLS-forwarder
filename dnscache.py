import config
import time
import collections

def _key_factory(tp, name):
    # 1: A
    # 2: NS
    # 5: CNAME
    # 15: MX
    # 16: TXT
    # 28: AAAA
    # 255: all
    prefix = "A" if tp == 1  else       \
             "N" if tp == 2  else       \
             "C" if tp == 5  else       \
             "M" if tp == 15 else       \
             "T" if tp == 16 else       \
             "6" if tp == 28 else       \
             "*" if tp == 255 else None   
    return prefix + name if prefix != None else None

_CacheEntry = collections.namedtuple("_CacheEntry", "data expire")

class DnsCache:

    def __init__(self, min_size = config.MIN_NUM_CACHE_ENTRY, max_size = config.MAX_NUM_CACHE_ENTRY):
        self._counter = 0  # rought counter, NOT accurate
        self._min_size = min_size
        self._max_size = max_size
        self._map = collections.OrderedDict()
    
    def cache(self, tp, name, ttl, data):

        if ttl == 0:
            return

        key = _key_factory(tp, name)

        if key == None:
            return
        
        if self._counter >= self._max_size:
            self.clean()

        self._map[key] = _CacheEntry(data, ttl + int(time.time()))

        # Not we may double count here, in case cache already exist. i.e.
        # a query comes in while another query of the same type and name
        # is pending.  
        self._counter = self._counter + 1
        
    def get(self, tp, name):

        key = _key_factory(tp, name)
        if key == None:
            return False, None

        entry = self._map.get(key, None)

        if entry == None:
            return False, None
        
        if entry.expire > int(time.time()):
            # pylint: disable=E1101
            self._map.move_to_end(key)
            # pylint: enable=E1101
            return True, entry.data
        else:
            del self._map[key]
            self._counter = self._counter - 1
            return False, None


    def clean(self):

        current = int(time.time())
        expired = list()

        expired = [ item[0] for item in self._map.items() if item[1].expire <= current]
        
        for expired_key in expired:
            del self._map[expired_key]
        
        for _ in range(len(self._map) - self._min_size):
            self._map.popitem(last = False)

        self._counter = self._min_size
