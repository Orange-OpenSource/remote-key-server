FROM python:3.7.3-slim-stretch

WORKDIR  /tests/

RUN  pip install Flask
RUN pip install flask-httpauth

COPY mock-callback-server/ mock-callback-server/
COPY mock-callback-server/cert/ /cert/

CMD ["python", "mock-callback-server/server.py"]

