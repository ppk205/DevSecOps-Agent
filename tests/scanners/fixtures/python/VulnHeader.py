from flask import make_response, request


def greeting():
    name = request.args.get("name")
    resp = make_response("hello")
    resp.headers["X-User"] = name
    return resp
