FROM golang:latest

RUN mkdir -p /home/app

WORKDIR /home/app

COPY . .

RUN go mod tidy

CMD ["go", "run", "main.go"]