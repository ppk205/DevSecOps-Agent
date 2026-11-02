from flask import request
from jinja2 import Template


def render():
    tpl = request.args.get("tpl")
    return Template(tpl).render()
