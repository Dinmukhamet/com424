FROM python:3.8-slim

WORKDIR /app

COPY Pipfile Pipfile.lock ./

RUN pip install pipenv && \
    apt-get update && \
    apt-get install -y --no-install-recommends gcc python3-dev libssl-dev && \
    pipenv install

COPY . .

ENTRYPOINT [ "pipenv", "run", "python3", "main.py" ]