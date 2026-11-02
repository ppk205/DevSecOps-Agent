import requests
from flask import request


def fetch():
    url = request.args.get("url")
    return requests.get(url, timeout=5).text
