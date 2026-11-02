import random


def make_token():
    return "%06d" % random.randint(0, 999999)
