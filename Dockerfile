FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /spidercob ./cmd/spidercob

FROM gcr.io/distroless/static-debian12
COPY --from=build /spidercob /spidercob
ENTRYPOINT ["/spidercob"]
CMD ["-config", "/config.json"]
