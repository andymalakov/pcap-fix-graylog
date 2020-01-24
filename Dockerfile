FROM golang:1.13

COPY ./src /go/src/
WORKDIR /go/src/pcap2graylog/

RUN go build capture.go

CMD ["./capture"]
