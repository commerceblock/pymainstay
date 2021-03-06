FROM python:3.8.2

COPY . /usr/src

RUN set -x \
    && cd /usr/src \
    && pip install -r requirements.txt \
    && python setup.py build \
    && python setup.py install

WORKDIR /usr/src

CMD ["bash", "-c"]
