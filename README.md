# Intro
This is a simple OIDC adapter acting as Relying Party in the Gematik OIDC Federation (GesundheitsID) and providing standard OIDC for clients.
Clients use standard OIDC code flow and the adapter translates the request to OIDC federation.
As a result, an id_token is returned with a claim containing KVNR.

# Quick Start
- Spin up the docker compose file in src directory
- Add entry to your hosts file (/etc/hosts) for _rp_ pointing to _127.0.0.1_ (needed to make the redirects work)
- Navigate to http://localhost:8088/realms/testadapter/account/#/ and click on "sign in"
  -  "Gesundheits-ID Custom Theme" has a fake login button enabled that will issue a (fake) id_token to keycloak

# Notes
- Only Code Flow is supported
- Only confidential clients supported (if you have an app, you can use it anyway, but the client_secret wont be secure...)
- Only scope "oidc" supported and must be present in request
- Usage of PKCE/S256 is mandatory
- No refresh token supported (for this usecase not needed)
- UserInfo endpoint does not return any additional data. It is implemented because some clients need it to work.
- Only KVNR is requested as scope at the moment. Our projects do not need user's email or any other additional data.
- The returned sub claim is unique for a distinct user (calculated from iss and sub of sec IdP). See "A_23035 - pseudonymes Attribut "sub""

See discovery document for more information on configuration options.

# Prerequisites
- Request X-Authorization Header value from Gematik to be able to test against Gematik sectorial IdP and add it to environment (see compose file)
- Set your private keys in configuration, deploy and register your IdP with Gematik (dont use the default keys - for obvious reasons...)

# Insurance Selection
See docker compose for an example on how to add additional styles. You can also overwrite the default page by mounting a volume.

## "In App" Insurance Selection
The insurance seletion can be done outside of this project (e.g. inside an app).
For this you have to set the login_hint parameter in the authorization request to the vaule of the selected id retrieved from idp endpoint.

# Docker Compose
The compose file starts the following services:
- OIDC Adapter
- Keycloak (configured to use the adapter as external identity provider)
- Redis (required for environment==production)
- Services to work with OpenTelemetry Tracing, Metrics and Logging

# Limitations & TODOs
- Requirement: A_23042 - Verifikation der Certificate Transparency für TLS Verbindungen in die VAU
  - This req is not implemented in code. Instead we use a curated list of ca-certificates when building the container. This is not part of this project.
- Additional security aspects are covered by our infrstructure (using reverse proxy, TLS enforcement, WAF, etc.).
- Requirement: A_23037 - Robustheit bei fehlenden Daten
  - Not yet implemented. The service will error out if a user rejects to provide the KVNR
- Only KVNR is rerquested for a user. Feel free to add code for additional scopes (using a pull request)
- JWT decryption using ES256 is not possible out of the box using dotnet running on linux. Therefore jose-jwt is used. The needed code is not yet part of the main repo, so the following PR has been copied: https://github.com/dvsekhvalnov/jose-jwt/pull/232
