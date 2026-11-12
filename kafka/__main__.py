"""Allow ``python -m kafka`` as an alternative to the ``kafka`` console script."""

from kafka.main import app

if __name__ == "__main__":
    app(prog_name="kafka")
