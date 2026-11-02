from flask import redirect, request, url_for


def go():
    page = request.args.get("page")
    return redirect(url_for(page))
