FROM golang:1.25-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/hostsentry-server ./cmd/hostsentry-server

FROM alpine:3.21
RUN apk add --no-cache ca-certificates curl && addgroup -S hostsentry && adduser -S -G hostsentry -H hostsentry
COPY --from=build /out/hostsentry-server /usr/local/bin/hostsentry-server
USER hostsentry
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/hostsentry-server"]
