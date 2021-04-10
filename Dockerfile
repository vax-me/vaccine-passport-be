FROM golang:1.16-alpine

WORKDIR /app
COPY . .

ENV GO111MODULE=on

RUN go get
RUN go build

ARG PRIVATE_KEY
ARG MONGO_STR

ENV VaccinePassportPrivateKey=${PRIVATE_KEY}
ENV VaccinePassportMongoUrl=${MONGO_STR}

EXPOSE 8010
CMD ["vaccine-passport-signing"]
