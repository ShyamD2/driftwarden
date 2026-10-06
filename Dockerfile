# Multi-stage distroless build for DriftWarden (< 25MB final image)
FROM golang:alpine AS builder

WORKDIR /src

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Build static binary
COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build \
    -ldflags="-w -s -X main.version=1.0.0" \
    -trimpath \
    -o /bin/driftwarden ./cmd/driftwarden

# Distroless static runtime
FROM gcr.io/distroless/static-debian12:nonroot@sha256:6cd22a017e9062634d0263f910445d4a1aa6ebc45a55743455122143ad078513

USER nonroot:nonroot
WORKDIR /home/nonroot

COPY --from=builder /bin/driftwarden /usr/local/bin/driftwarden

ENTRYPOINT ["/usr/local/bin/driftwarden"]
CMD ["scan"]
