
FROM ubuntu:14:04

# get latest install
RUN apt-get update && apt-get install -yq wireshark

# prepare a wireshark-user and his home-directory
ENV HOME /home/wireshark

RUN useradd --create-home --homedir $HOME wireshark
RUN chown -R wireshark: wireshark $HOME

USER wireshark

WORKDIR wireshark

ADD ./wireshark/plugins ${HOME}/.wireshark/plugins

ENTRYPOINT ["wireshark"]

