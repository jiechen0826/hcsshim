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

FROM mcr.microsoft.com/windows/servercore:ltsc2022@sha256:a264df8cd8c329eed3fd1e0cafcd4f3dc453e2c72a277f9bb140fd6f10a2eefc
WORKDIR /app
COPY --from=build /app/delayed-shutdown.exe .
ENTRYPOINT ["delayed-shutdown.exe"]
