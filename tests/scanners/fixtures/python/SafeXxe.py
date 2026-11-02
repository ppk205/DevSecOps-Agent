import defusedxml.ElementTree as DET


def parse_upload(data):
    return DET.fromstring(data)
