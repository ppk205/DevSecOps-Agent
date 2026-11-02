import ldap
from ldap.filter import escape_filter_chars


def find_user(username):
    conn = ldap.initialize("ldap://localhost")
    filt = "(uid=" + escape_filter_chars(username) + ")"
    return conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, filt)
