FROM alpine:3.20
RUN apk add --no-cache openssl iproute2
COPY generate-cert.sh /generate-cert.sh
RUN chmod +x /generate-cert.sh
VOLUME ["/certs"]
ENTRYPOINT ["/generate-cert.sh"]
