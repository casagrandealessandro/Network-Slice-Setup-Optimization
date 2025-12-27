FROM docker:stable-dind

RUN apk update && apk upgrade

RUN apk add bash
RUN apk add iproute2 busybox-extras iperf

RUN apk add stress-ng curl tcpdump netcat-openbsd

ENV HOME /root
WORKDIR /root

# Define default command.
CMD ["bash"]