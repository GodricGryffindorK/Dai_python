FROM ubuntu:18.04
LABEL Maintainer="Christian Doerr"

RUN apt-get update
RUN apt-get -y install curl nano openjdk-11-jdk python3 python3-pip build-essential libpcap-dev golang-go libtins-dev
RUN pip3 install libpcap dpkt pcapy pypcap scapy

WORKDIR "/tmp"
