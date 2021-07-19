FROM golang:1.16.6-alpine

WORKDIR /app
COPY go.mod .
COPY go.sum .
COPY main.go .

ENV GO111MODULE=on

RUN go mod download

COPY . .
RUN go build

ENV VaccinePassportPrivateKey=""
ENV VaccinePassportMongoUrl=""
ENV VaccinePassportAuthAud=""
ENV VaccinePassportSUEmail=""
ENV VaccinePassportAuthIss=""

EXPOSE 8010
ENTRYPOINT ["/app/vaccine-passport-signing"]
