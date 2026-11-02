from flask import request


def read_file():
    name = request.args.get("name")
    with open("/data/" + name) as handle:
        return handle.read()
