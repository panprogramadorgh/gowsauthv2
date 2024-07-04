FROM golang:latest

RUN mkdir -p /home/app/bin

WORKDIR /home/app

COPY ./go.* ./

COPY ./main.go ./

COPY ./index.html ./bin

RUN go mod tidy

RUN go build -o ./bin/main ./main.go

CMD ["./bin/main"]