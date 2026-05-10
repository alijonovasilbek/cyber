FROM python:3.11-slim

RUN pip install --no-cache-dir paramiko requests

COPY attack.py /attack.py

CMD ["python3", "-u", "/attack.py"]
