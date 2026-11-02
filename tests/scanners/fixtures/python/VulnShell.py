import subprocess


def show_log(branch):
    return subprocess.run("git log " + branch, shell=True, capture_output=True)
