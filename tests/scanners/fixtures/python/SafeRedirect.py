from flask import redirect, url_for


def go():
    return redirect(url_for("index"))
