FROM golang:1.17-bullseye

WORKDIR /walk
COPY scripts/download-log4j.sh download-log4j.sh
RUN ./download-log4j.sh
WORKDIR /app
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY . ./
RUN go build -o /scan4log4shell 