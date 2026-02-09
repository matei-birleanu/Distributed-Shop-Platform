FROM python:3.13-slim

WORKDIR /app

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
    python-dotenv==1.0.1

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/health', timeout=5)"

CMD ["python", "app.py"]

