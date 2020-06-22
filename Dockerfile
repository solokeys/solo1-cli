FROM ubuntu:bionic

RUN apt update
RUN apt install -qy make python3 python3-pip python3-venv git
RUN mkdir -p /app

WORKDIR /app
