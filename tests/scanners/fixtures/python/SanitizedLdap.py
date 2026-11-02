import ldap
from flask import request
from ldap.filter import escape_filter_chars


def find_user():
    username = request.args.get("username")
    conn = ldap.initialize("ldap://localhost")
    return conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, escape_filter_chars(username))
