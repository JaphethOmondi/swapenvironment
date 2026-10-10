"""Production WSGI entrypoint: gunicorn -w 4 -b 0.0.0.0:8000 wsgi:app"""

from swapguard import create_app

app = create_app("production")
