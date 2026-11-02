import jwt


def make_token(user):
    return jwt.encode({"user": user}, "supersecret", algorithm="HS256")
