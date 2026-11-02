from jinja2 import Environment, FileSystemLoader

ENV = Environment(loader=FileSystemLoader("templates"))


def render(name):
    return ENV.get_template("page.html").render(name=name)
