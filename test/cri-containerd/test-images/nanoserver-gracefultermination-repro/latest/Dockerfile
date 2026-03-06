# Test image for graceful termination CRI integration tests.
# `docker build -t cplatpublic.azurecr.io/nanoserver-gracefultermination-repro:latest .`
# `docker push cplatpublic.azurecr.io/nanoserver-gracefultermination-repro:latest`

FROM  golang:latest as build
ENV GOOS=windows
ENV GOARCH=amd64
ENV GO111MODULE=off
WORKDIR /app
COPY ./delayed-shutdown.go ./
RUN go build -o delayed-shutdown.exe

FROM mcr.microsoft.com/windows/nanoserver:ltsc2022@sha256:60612a30303eb5a15ce7f53fa2eecf70bca41d72657de0482fbde601ae5f3403
WORKDIR /app
COPY --from=build /app/delayed-shutdown.exe .
ENTRYPOINT ["delayed-shutdown.exe"]
