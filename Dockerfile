FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y openssh-client sshpass && \
    rm -rf /var/lib/apt/lists/*

COPY . .

RUN pip install -r requirements.txt

CMD ["python", "-u", "main.py"]