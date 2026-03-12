# Test image for graceful termination CRI integration tests.
# `docker build -t cplatpublic.azurecr.io/servercore-gracefultermination-repro:latest .`
# `docker push cplatpublic.azurecr.io/servercore-gracefultermination-repro:latest`

FROM  golang:latest as build
ENV GOOS=windows
ENV GOARCH=amd64
ENV GO111MODULE=off
WORKDIR /app
COPY ./delayed-shutdown.go ./
RUN go build -o delayed-shutdown.exe

FROM mcr.microsoft.com/windows/servercore:ltsc2022@sha256:d4c6d1a8a1a306b12691c3b2e5e3a8bfad786cbd6b7831cd74a9a6a99eab08ad
WORKDIR /app
COPY --from=build /app/delayed-shutdown.exe .
ENTRYPOINT ["delayed-shutdown.exe"]
