import ldap
from flask import request


def find_user():
    username = request.args.get("username")
    conn = ldap.initialize("ldap://localhost")
    return conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=" + username + ")")
