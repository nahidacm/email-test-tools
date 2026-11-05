# Build CSS
FROM node:22-alpine AS css
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci
COPY web ./web
RUN npm run build:css

# Build binary
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
COPY --from=css /src/web/static/assets/app.css web/static/assets/app.css
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=${VERSION}" -o /email-test-tools .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /email-test-tools /email-test-tools
EXPOSE 8587
# Inside a container we must listen on all interfaces; publish only to localhost:
#   docker run --rm -p 127.0.0.1:8587:8587 email-test-tools
ENTRYPOINT ["/email-test-tools", "--no-browser", "--addr", "0.0.0.0:8587"]
