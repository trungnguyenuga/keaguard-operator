# Linux amd64 M1 baseline, resolved and verified during T01.
FROM docker.io/library/golang:1.27.2@sha256:820153096fda4de6ac1b7194d12e416b7dd8f4e9a33d17e0345b111b945162d8 AS builder
ENV GOTOOLCHAIN=local
WORKDIR /workspace
RUN test "$(go version)" = "go version go1.27.2 linux/amd64"
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY api/ api/
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /manager ./cmd

FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
WORKDIR /
COPY --from=builder /manager /manager
USER 65532:65532
ENTRYPOINT ["/manager"]
