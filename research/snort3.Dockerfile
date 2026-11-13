# Snort 3 is not packaged for Ubuntu 24.04; Alpine 3.24 ships 3.9.2.0.
# In a Claude cloud session the build needs the session proxy and its CA (see setup_tools.sh).
FROM alpine:3.24
ARG HTTPS_PROXY
ARG HTTP_PROXY
COPY ca-bundle.crt /etc/ssl/certs/ca-certificates.crt
RUN https_proxy=$HTTPS_PROXY http_proxy=$HTTP_PROXY apk add --no-cache snort
