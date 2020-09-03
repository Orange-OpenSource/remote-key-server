FROM python:3.8-alpine

RUN pip install requests

ADD ./client-node.py /client-node.py
ADD ./ssl /ssl

EXPOSE 8443
ENTRYPOINT ["python3", "/client-node.py"]
