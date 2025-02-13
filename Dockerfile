FROM golang:1.24.0-alpine AS builder

WORKDIR /go/src/github.com/larivierec/aws-es-proxy
COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT=""

ENV GOOS=linux
ENV GOARCH=amd64
ARG VERSION=dev
ARG REVISION=dev

ENV CGO_ENABLED=0 \
      GO111MODULE=on \
      GOOS=${TARGETOS} \
      GOARCH=${TARGETARCH} \
      GOARM=${TARGETVARIANT}

RUN go mod download
RUN go build -ldflags "-s -w -X main.Version=${VERSION} -X main.Gitsha=${REVISION}" -o aws-es-proxy aws-es-proxy.go

FROM alpine:3.21
LABEL name="aws-es-proxy" \
      version="latest"

RUN apk --no-cache add ca-certificates
WORKDIR /home/
COPY --from=builder /go/src/github.com/larivierec/aws-es-proxy/aws-es-proxy /usr/local/bin/

ENV PORT_NUM=9200
EXPOSE ${PORT_NUM}

ENTRYPOINT ["aws-es-proxy"] 
CMD ["-h"]
