def find(conn, uid):
# ruleid: python.ldap.search-filter-dynamic
    return conn.search_s("dc=x", 2, "(uid=" + uid + ")")


def find_safe(conn):
# ok: python.ldap.search-filter-dynamic
    return conn.search_s("dc=x", 2, "(uid=fixed)")
