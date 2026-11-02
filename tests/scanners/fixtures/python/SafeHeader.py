from flask import make_response


def greeting():
    resp = make_response("hello")
    resp.headers["X-Version"] = "1.0"
    return resp
