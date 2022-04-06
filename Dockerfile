#build stage
FROM golang:alpine AS builder
RUN apk add --no-cache git
WORKDIR /go/src/app
COPY . .
RUN go get -d -v ./...
RUN go build -o /go/bin/app -v ./...

#final stage
FROM aquasec/trivy:latest
ENV IS_DOCKER=true
COPY --from=builder /go/bin/app /app
ENTRYPOINT /app
LABEL Name=terraformhelmscanning Version=0.0.1
