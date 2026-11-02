import subprocess


def list_data():
    return subprocess.run(["ls", "/data"], shell=False, capture_output=True)
