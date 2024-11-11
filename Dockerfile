FROM python:3.13-slim-bookworm AS python3

MAINTAINER Lavrenkov N.V <larenkovnv@gmail.com> <lavrenkovnv@oblgas.by>

# PYTHON REQ
COPY requirements.txt .
RUN pip3 install -r requirements.txt

WORKDIR /app
COPY ./app .
CMD ["python3", "egts.py"]
