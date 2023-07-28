FROM golang:1.20-buster AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 make

FROM debian:bookworm-slim

COPY LICENSE /usr/local/share/loopy-dns/
COPY --from=builder /app/bin/loopy-dns /usr/local/bin/

EXPOSE 5353/udp
ENTRYPOINT ["/usr/local/bin/loopy-dns"]