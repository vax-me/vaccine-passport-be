FROM golang:1.16-alpine

WORKDIR /app
COPY . .

ENV GO111MODULE=on

RUN go get
RUN go build

ENV VaccinePassportPrivateKey=""
ENV VaccinePassportMongoUrl=""
ENV VaccinePassportAuthAud=""
ENV VaccinePassportSUEmail=""

EXPOSE 8010
ENTRYPOINT ["/app/vaccine-passport-signing"]
