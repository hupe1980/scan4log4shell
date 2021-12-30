FROM golang:1.17-bullseye as build-env
WORKDIR /app
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /scan4log4shell 
FROM scratch
COPY --from=build-env /scan4log4shell /scan4log4shell
ENTRYPOINT ["/scan4log4shell"]