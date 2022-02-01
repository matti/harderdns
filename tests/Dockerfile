FROM alpine

RUN apk add bash bind-tools libcap

COPY --from=mattipaksula/harderdns:sha-e5433e8 /* /usr/local/bin
RUN setcap CAP_NET_BIND_SERVICE=+eip /usr/local/bin/harderdns

RUN adduser -D app

WORKDIR /app
COPY app .

USER app
ENTRYPOINT [ "/app/entrypoint.sh" ]