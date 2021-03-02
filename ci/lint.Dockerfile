FROM python:3.6

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y libusb-1.0-0-dev

RUN pip install poetry flake8

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV LANGUAGE=C.UTF-8
