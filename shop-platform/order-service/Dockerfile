FROM python:3.13-slim

WORKDIR /app

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY app.py .

RUN pip install --no-cache-dir \
    flask==3.1.2 \
    flask-cors==5.0.0 \
    requests==2.32.5 \
    sqlalchemy==2.0.36 \
    psycopg2-binary==2.9.10 \
    python-keycloak==4.2.2 \
    pyjwt==2.9.0 \
    cryptography==44.0.0 \
    python-dotenv==1.0.1 \
    stripe==7.9.0

EXPOSE 5002

CMD ["python", "app.py"]

