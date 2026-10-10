#!/bin/bash
# Whether a Spring Boot OAuth2 client fetches its provider's JWK set and user info over plain HTTP
# or TLS during a login (authorization_code) flow, and what an answer from that endpoint decides:
# the reference for jwk-set-uri and user-info-uri (VALIDATION.md, "OAuth2 Client login-flow
# transport scenarios").
#
# There is no authorization server and no browser. oauth2-login-transport/login_listener.py on
# 127.0.0.1:8301 answers the token endpoint (an access token and, for OpenID Connect, an ID token
# RS256-signed with a throwaway key), the JWK set and the user info, and records each request ("TLS"
# when the client opens a TLS handshake, "+token" when the request carries the access token). Each
# scenario starts the oauth2-login-transport app (Spring Boot 4.1.1, its auto-configured
# oauth2Login) on port 8090 with the properties as command-line arguments, then plays the browser
# with curl: GET /oauth2/authorization/scg, read state and nonce from the redirect to
# authorization-uri (never contacted), call the callback /login/oauth2/code/scg with them (the
# nonce as the code, so the listener can put it in the ID token), and GET /me with the session
# cookie. It prints the requests the listener saw, where the callback redirected ("/" when
# the login succeeded) and the user /me names.
#
# token-uri is plain HTTP in every scenario: the client must get a token for the flow to reach the
# endpoints under test, and that exchange is measured on its own (oauth2-client-transport-scenarios.sh).
set -u
cd "$(dirname "$0")"
(cd oauth2-login-transport && mvn -q package -DskipTests) || exit 1
JAR=oauth2-login-transport/target/oauth2-login-transport.jar
T=oauth2-login-transport/target/scenario
mkdir -p "$T"
LOG=$T/app.log
SEEN=$T/seen.txt
JAR_COOKIES=$T/cookies.txt

for port in 8090 8301; do
    if (echo > /dev/tcp/127.0.0.1/$port) 2>/dev/null; then
        echo "port $port already in use: stop the process holding it first" >&2
        exit 1
    fi
done
[ -f "$T/signing-key.pem" ] || openssl genrsa -out "$T/signing-key.pem" 2048 2>/dev/null || exit 1
[ -f "$T/other-key.pem" ] || openssl genrsa -out "$T/other-key.pem" 2048 2>/dev/null || exit 1

: > "$SEEN"
python3 oauth2-login-transport/login_listener.py "$SEEN" 8301 "$T" &
LISTENER_PID=$!
trap 'kill $LISTENER_PID 2>/dev/null' EXIT
for _ in $(seq 1 10); do (echo > /dev/tcp/127.0.0.1/8301) 2>/dev/null && break; sleep 1; done
sleep 1
: > "$SEEN"

L=http://127.0.0.1:8301
R=--spring.security.oauth2.client.registration.scg
P=--spring.security.oauth2.client.provider.scg
OIDC="$R.scope=openid,profile $P.user-name-attribute=sub"
OAUTH2="$R.scope=read $P.user-name-attribute=sub"

param() { # name, URL: the query parameter's value
    echo "$2" | grep -oE "[?&]$1=[^&]*" | head -1 | cut -d= -f2-
}

scenario() { # name, JWK set key file, user info "<sub>" or "<sub>/<name>" (name defaults to sub), arguments
    local name=$1 key=$2 subject=$3; shift 3
    echo "$key" > "$T/jwks-key"
    echo "${subject%%/*}" > "$T/userinfo-sub"
    echo "${subject#*/}" > "$T/userinfo-name"
    rm -f "$JAR_COOKIES"
    while (echo > /dev/tcp/127.0.0.1/8090) 2>/dev/null; do sleep 1; done
    java -jar "$JAR" --server.port=8090 $R.client-id=scg-client $R.client-secret=scg-client-secret \
        $R.authorization-grant-type=authorization_code $R.provider=scg "$R.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}" \
        $P.authorization-uri=$L/authorize $P.token-uri=$L/token "$@" > "$LOG" 2>&1 &
    local pid=$!
    for _ in $(seq 1 60); do
        grep -q "Started OAuth2LoginApp in\|APPLICATION FAILED\|Application run failed" "$LOG" && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    if ! grep -q "Started OAuth2LoginApp in" "$LOG"; then
        printf '%-58s did not start\n' "$name"
        kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
        return
    fi
    : > "$SEEN"
    local authorize state nonce callback user
    authorize=$(curl -s -c "$JAR_COOKIES" -o /dev/null -w '%{redirect_url}' http://localhost:8090/oauth2/authorization/scg)
    state=$(param state "$authorize")
    nonce=$(param nonce "$authorize")
    callback=$(curl -s -b "$JAR_COOKIES" -c "$JAR_COOKIES" -o /dev/null -w '%{redirect_url}' \
        "http://localhost:8090/login/oauth2/code/scg?code=${nonce:--}&state=$state")
    user=$(curl -s -b "$JAR_COOKIES" -o /dev/null -w '%{http_code}' http://localhost:8090/me)
    [ "$user" = 200 ] && user=$(curl -s -b "$JAR_COOKIES" http://localhost:8090/me) || user="(not logged in)"
    sleep 1
    printf '%-58s %-38s callback=%-26s me=%s\n' "$name" "$(sort "$SEEN" | uniq | tr '\n' ' ')" \
        "${callback#http://localhost:8090}" "$user"
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
}

S=signing-key.pem
O=other-key.pem
scenario "J1 OIDC, jwk-set-uri=http://"                          $S scg-user $OIDC $P.jwk-set-uri=$L/jwks
scenario "J2 OIDC, jwk-set-uri=https://"                         $S scg-user $OIDC $P.jwk-set-uri=https://127.0.0.1:8301/jwks
scenario "J3 OIDC, jwk-set-uri=http://, keys the token isn't signed with" $O scg-user $OIDC $P.jwk-set-uri=$L/jwks
scenario "J4 OAuth2 (no openid), jwk-set-uri=http://"            $S scg-user $OAUTH2 $P.jwk-set-uri=$L/jwks $P.user-info-uri=$L/userinfo
scenario "U1 OIDC, user-info-uri=http://"                        $S scg-user $OIDC $P.jwk-set-uri=$L/jwks $P.user-info-uri=$L/userinfo
scenario "U2 OIDC, scope=openid only, user-info-uri=http://"     $S scg-user $R.scope=openid $P.user-name-attribute=sub $P.jwk-set-uri=$L/jwks $P.user-info-uri=$L/userinfo
scenario "U3 OIDC, user-info-uri=http:// answers another sub"    $S admin    $OIDC $P.jwk-set-uri=$L/jwks $P.user-info-uri=$L/userinfo
scenario "U4 OIDC, user-name-attribute=email, user info: another email" $S scg-user/admin $R.scope=openid,profile $P.user-name-attribute=email $P.jwk-set-uri=$L/jwks $P.user-info-uri=$L/userinfo
scenario "U5 OIDC, user-name-attribute=preferred_username, user info: admin" $S scg-user/admin $R.scope=openid,profile $P.user-name-attribute=preferred_username $P.jwk-set-uri=$L/jwks $P.user-info-uri=$L/userinfo
scenario "U6 OIDC, user-info-uri=https://"                       $S scg-user $OIDC $P.jwk-set-uri=$L/jwks $P.user-info-uri=https://127.0.0.1:8301/userinfo
scenario "N1 OAuth2, user-info-uri=http://"                      $S scg-user $OAUTH2 $P.user-info-uri=$L/userinfo
scenario "N2 OAuth2, user-info-uri=http:// answers another sub"  $S admin    $OAUTH2 $P.user-info-uri=$L/userinfo
scenario "N3 OAuth2, user-info-uri=https://"                     $S scg-user $OAUTH2 $P.user-info-uri=https://127.0.0.1:8301/userinfo
exit 0
