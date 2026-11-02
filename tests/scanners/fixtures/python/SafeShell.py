import subprocess


def show_log(branch):
    return subprocess.run(["git", "log", branch], shell=False, capture_output=True)
