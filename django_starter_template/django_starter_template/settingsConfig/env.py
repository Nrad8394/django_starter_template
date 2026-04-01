import os


def get_env(variable_name, default=None, required=False, cast=str):
    value = os.environ.get(variable_name, default)

    if required and value is None:
        raise Exception(f"Missing required env variable: {variable_name}")

    try:
        return cast(value) if value is not None else value
    except Exception:
        raise Exception(f"Invalid value for {variable_name}")
