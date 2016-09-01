FROM python:2.7.12

RUN apt-get update && apt-get install -qy python-dev python-pip git libffi-dev libssl-dev procps iptables graphviz && apt-get clean all

RUN mkdir -p /opt/iptables

RUN pip install git+https://github.com/allanhung/dot-iptables.git@master

WORKDIR /opt/iptables

EXPOSE 8000

CMD iptables-save|dotiptables --render && python -m SimpleHTTPServer 8000
