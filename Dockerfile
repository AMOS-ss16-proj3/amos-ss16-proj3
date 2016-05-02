
FROM ubuntu:14.04

RUN apt-get update && apt-get install -yq wireshark

ENV HOME /home/wireshark

RUN useradd --create-home --homedir $HOME wireshark
RUN chown -R wireshark: wireshark $HOME

USER wireshark

WORKDIR wireshark

ADD ./wireshark/plugins ${HOME}/.wireshark/plugins

ENTRYPOINT ["wireshark"]

