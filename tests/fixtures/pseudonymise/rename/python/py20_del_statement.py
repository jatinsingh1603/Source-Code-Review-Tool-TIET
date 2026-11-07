def clear(cache_map, stale_key):
    del cache_map[stale_key]
    scratch_value = 1
    del scratch_value
