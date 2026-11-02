from flask import request
from markupsafe import Markup, escape


def greet():
    name = request.args.get("name")
    return Markup(escape(name))
