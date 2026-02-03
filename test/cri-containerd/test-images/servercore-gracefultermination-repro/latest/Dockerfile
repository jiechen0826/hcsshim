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

FROM mcr.microsoft.com/windows/servercore:ltsc2022@sha256:3750d7fcd320130cc2ce61954902b71729e85ec2c07c5a2e83a6d6c7f34a61e5
WORKDIR /app
COPY --from=build /app/delayed-shutdown.exe .
ENTRYPOINT ["delayed-shutdown.exe"]
