def get_user(cur, username):
    cur.execute("SELECT * FROM users WHERE name = %s", (username,))
    return cur.fetchone()
