import dill


def load_session(data):
    return dill.loads(data)
