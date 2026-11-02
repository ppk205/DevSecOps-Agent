import os

import jwt


def make_token(user):
    return jwt.encode({"user": user}, os.environ["JWT_SECRET"], algorithm="RS256")
