import os
import shlex
from flask import request


def list_dir():
    target = request.args.get("target")
    os.system("ls " + shlex.quote(target))
