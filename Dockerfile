FROM golang:1.17.6-alpine as builder

COPY . /app/
WORKDIR /app
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o harderdns .

FROM scratch
COPY --from=builder /app/harderdns /harderdns
ENTRYPOINT [ "/harderdns" ]