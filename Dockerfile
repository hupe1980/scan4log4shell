FROM golang:1.17-bullseye
WORKDIR /app
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY . ./
RUN GOOS=linux go build -o /scan4log4shell 
ENTRYPOINT ["/scan4log4shell"]