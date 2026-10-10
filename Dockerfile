FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Never run as root in a container.
RUN useradd -m -u 1000 swapguard && chown -R swapguard:swapguard /app
USER swapguard

EXPOSE 8000

# Gunicorn, not flask run: the dev server is single-threaded and its debug
# mode exposes an interactive console on any traceback.
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", \
     "--access-logfile", "-", "--error-logfile", "-", \
     "--timeout", "30", "wsgi:app"]
