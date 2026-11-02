import xml.etree.ElementTree as ET


def parse_upload(data):
    return ET.fromstring(data)
