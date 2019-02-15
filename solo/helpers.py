def to_websafe(data):
    data = data.replace("+", "-")
    data = data.replace("/", "_")
    data = data.replace("=", "")
    return data


def from_websafe(data):
    data = data.replace("-", "+")
    data = data.replace("_", "/")
    return data + "=="[: (3 * len(data)) % 4]
