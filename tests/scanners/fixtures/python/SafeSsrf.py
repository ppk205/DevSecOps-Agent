import requests


def health():
    return requests.get("https://api.example.com/health", timeout=5).text
