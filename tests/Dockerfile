FROM alpine

RUN apk add bash bind-tools libcap

COPY --from=harderdns:latest /* /usr/local/bin
RUN setcap CAP_NET_BIND_SERVICE=+eip /usr/local/bin/harderdns

RUN adduser -D app

WORKDIR /app
COPY app .

USER app
ENTRYPOINT [ "/app/entrypoint.sh" ]