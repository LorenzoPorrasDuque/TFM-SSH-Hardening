FROM golang:1.26-alpine as builder
WORKDIR /app

# cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# copy source
COPY . .

# build binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o api .

# ---------- runtime stage ----------
FROM alpine:3.20

WORKDIR /app

# copy compiled binary
COPY --from=builder /app/api .

# expose your API port (change if needed)
EXPOSE 8080

# run it
CMD ["./api"]