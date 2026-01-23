FROM nginx:alpine

RUN apk update && apk upgrade

RUN apk add --no-cache \
    bash \
    iproute2 \
    iperf3 \
    curl \
    tcpdump \
    netcat-openbsd \
    stress-ng