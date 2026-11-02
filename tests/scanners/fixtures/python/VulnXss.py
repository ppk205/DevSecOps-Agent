from flask import request
from markupsafe import Markup


def greet():
    name = request.args.get("name")
    return Markup("<b>" + name + "</b>")
