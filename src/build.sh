docker buildx build . -f ./RelyingParty/Dockerfile --platform linux/amd64,linux/arm64 -t mta-registry.k3-1.bym-dev.de/oidc-rp:latest --push
