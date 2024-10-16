docker buildx build . -f ./RelyingParty/Dockerfile --platform linux/amd64,linux/arm64 -t harbor.k3-1.bym-dev.de/medicalone/oidc-rp:env_test --push
