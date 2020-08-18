FROM python:3.7-slim-stretch

WORKDIR  /tests/

RUN pip install tox

COPY ./tests/rksclient  ./rksclient
COPY ./tests/tox.ini ./
COPY ./tests/test-requirements.txt  ./
COPY ./tests/testdata/ ./testdata/
COPY ./certs certs/

RUN tox --notest -e dockertest

COPY ./tests/test/ test/

CMD ["tox", "--", "--rks-url", "http://rks-server:8080"]
