
FROM ubuntu:14.04

RUN apt-get update
RUN apt-get install -y software-properties-common --no-install-recommends
RUN add-apt-repository ppa:wireshark-dev/stable
RUN apt-get update
RUN apt-get install -y wireshark
RUN rm -rf /var/lib/apt/lists/*

#RUN apt-get update && apt-get install -yq wireshark

ENV HOME /home/wireshark

RUN useradd --create-home --home-dir $HOME wireshark

RUN chown -R wireshark:wireshark $HOME

USER wireshark

WORKDIR wireshark

ADD ./plugins ${HOME}/.wireshark/plugins

ENTRYPOINT ["wireshark"]

