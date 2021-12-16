FROM golang:1.17-bullseye
COPY scripts/wait-for-vulnapp.sh /wait-for-vulnapp.sh
WORKDIR /app
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY . ./
RUN go build -o /scan4log4shell 