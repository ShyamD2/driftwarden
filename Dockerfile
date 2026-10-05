# Multi-stage distroless build for DriftWarden (< 25MB final image)
FROM golang:1.24-alpine AS builder

WORKDIR /src

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Build static binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=1.0.0" \
    -trimpath \
    -o /bin/driftwarden ./cmd/driftwarden

# Distroless static runtime
FROM gcr.io/distroless/static-debian12:nonroot

USER nonroot:nonroot
WORKDIR /home/nonroot

COPY --from=builder /bin/driftwarden /usr/local/bin/driftwarden

ENTRYPOINT ["/usr/local/bin/driftwarden"]
CMD ["scan"]
