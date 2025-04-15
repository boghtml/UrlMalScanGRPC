FROM golang:1.24-alpine

WORKDIR /app

COPY . .

RUN go mod download

RUN go build -o client_app ./client/cmd

EXPOSE 8080

CMD ["./client_app"]