#!/bin/bash
# What each logging setting writes to the application log, one configuration at a time: the
# reference SCG009 is checked against (VALIDATION.md, "SCG009 verbose logging scenarios").
#
# Each scenario starts the verbose-logging app (Spring Boot 4.1.1: Spring MVC, JdbcTemplate and
# JPA on H2, RestClient on Apache HttpClient 5) with the properties as command-line arguments,
# waits until the previous app has released the port and the new one has started, sends one
# POST /login?token=... with an Authorization header and a JSON body, and prints which secrets
# reached the log: Q = query parameter, H = inbound Authorization header, B = inbound body,
# S = JdbcTemplate bound parameter, J = JPA bound parameter, O = outbound Authorization header,
# D = outbound body ("-" = none). Y1-Y5, P1 and P2 load files written to target/ by this script:
# YAML values (unquoted off and no, which YAML reads as false, a quoted "off", and null), a
# properties file with an upper-case key, and one with a trailing space after false.
set -u
cd "$(dirname "$0")/verbose-logging"
mvn -q package -DskipTests || exit 1
JAR=target/verbose-logging.jar
LOG=target/scenario.log
PORT=8095

leaked() {
    local out="" pair
    for pair in Q:query-token-secret H:inbound-header-secret B:inbound-body-secret S:sql-param-secret \
        J:jpa-param-secret O:outbound-header-secret D:outbound-body-secret; do
        grep -q -- "${pair#*:}" "$LOG" && out+=${pair%%:*}
    done
    echo "${out:--}"
}

scenario() {
    local name=$1; shift
    local waited=0
    while (echo > /dev/tcp/localhost/$PORT) 2>/dev/null; do
        sleep 1
        waited=$((waited + 1))
        [ $waited -lt 60 ] || { echo "port $PORT still in use after 60s" >&2; exit 1; }
    done
    java -jar "$JAR" --server.port=$PORT "$@" > "$LOG" 2>&1 &
    local pid=$!
    for _ in $(seq 1 90); do
        grep -q "Started LoggingApp in\|APPLICATION FAILED" "$LOG" && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    if ! grep -q "Started LoggingApp in" "$LOG"; then
        printf '%-52s app did not start: %s\n' "$name" "$(grep -m1 -E '^ *Reason: ' "$LOG" | sed -E 's/^ *Reason: //')"
    else
        curl -s -o /dev/null -X POST "localhost:$PORT/login?token=query-token-secret" \
            -H 'Authorization: Bearer inbound-header-secret' -H 'Content-Type: application/json' \
            -d '{"password":"inbound-body-secret"}'
        sleep 1
        printf '%-52s leaked=%s\n' "$name" "$(leaked)"
    fi
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
}

L=--logging.level
scenario "L0 defaults"
scenario "L1 debug=true"                                 --debug=true
scenario "L2 debug=false"                                --debug=false
scenario "L3 debug=FALSE"                                --debug=FALSE
scenario "L4 debug=off"                                  --debug=off
scenario "L5 debug=no"                                   --debug=no
scenario "L6 debug=0"                                    --debug=0
scenario "L7 debug= (empty)"                             --debug=
scenario "L8 trace=true"                                 --trace=true
scenario "L9 trace=off"                                  --trace=off
printf 'debug: off\n' > target/unquoted-off.yml
scenario "Y1 YAML debug: off (unquoted)"                 --spring.config.additional-location=file:target/unquoted-off.yml
printf 'debug: no\n' > target/unquoted-no.yml
scenario "Y2 YAML debug: no (unquoted)"                  --spring.config.additional-location=file:target/unquoted-no.yml
printf 'DEBUG=true\n' > target/uppercase-key.properties
scenario "P1 properties file: DEBUG=true"                --spring.config.additional-location=file:target/uppercase-key.properties
printf 'debug=false \n' > target/trailing-space.properties
scenario "P2 properties file: 'debug=false ' (trailing space)" --spring.config.additional-location=file:target/trailing-space.properties
printf 'debug: "off"\n' > target/quoted-off.yml
scenario "Y3 YAML debug: \"off\" (quoted)"                --spring.config.additional-location=file:target/quoted-off.yml
printf 'debug:\n' > target/null.yml
scenario "Y4 YAML debug: (null)"                         --spring.config.additional-location=file:target/null.yml
printf 'debug: ~\n' > target/tilde.yml
scenario "Y5 YAML debug: ~"                              --spring.config.additional-location=file:target/tilde.yml
scenario "P3 debug=\${UNSET_VAR:} (empty default)"       '--debug=${UNSET_VAR:}'
scenario "P4 debug=\${UNSET_VAR:false}"                  '--debug=${UNSET_VAR:false}'
scenario "R1 logging.level.root=DEBUG"                   $L.root=DEBUG
scenario "R2 logging.level.root=TRACE"                   $L.root=TRACE
scenario "R3 logging.level.root=debug"                   $L.root=debug
scenario "R4 logging.level.root=INFO"                    $L.root=INFO
scenario "R5 logging.level.root=ALL"                     $L.root=ALL
scenario "R6 logging.level.root=true"                    $L.root=true
scenario "N1 logging.level.web=debug"                    $L.web=debug
scenario "N2 logging.level.sql=debug"                    $L.sql=debug
scenario "N3 logging.level.org.springframework=trace"    $L.org.springframework=trace
scenario "N7 logging.level.org.springframework.web=debug" $L.org.springframework.web=debug
scenario "N4 ...org.hibernate.orm.jdbc.bind=trace"       $L.org.hibernate.orm.jdbc.bind=trace
scenario "N5 ...org.apache.hc.client5.http.wire=debug"   $L.org.apache.hc.client5.http.wire=debug
scenario "N8 logging.level.org.springframework=debug"    $L.org.springframework=debug
scenario "N9 logging.level.org=debug"                    $L.org=debug
scenario "N10 logging.level.sql=trace"                   $L.sql=trace
scenario "N11 ...org.springframework.jdbc.core=trace"    $L.org.springframework.jdbc.core=trace
scenario "N12 logging.level.org.hibernate=trace"         $L.org.hibernate=trace
scenario "N13 logging.level.org.apache.hc=debug"         $L.org.apache.hc=debug
scenario "N14 logging.level.org.apache.hc=info"          $L.org.apache.hc=info
scenario "N6 spring.mvc.log-request-details, web=debug"  --spring.mvc.log-request-details=true $L.web=debug
# The loggers that write each secret, one at a time, at the level that turns them on.
scenario "N15 ...web.servlet.DispatcherServlet=debug"    $L.org.springframework.web.servlet.DispatcherServlet=debug
scenario "N16 ...RequestResponseBodyMethodProcessor=debug" $L.org.springframework.web.servlet.mvc.method.annotation.RequestResponseBodyMethodProcessor=debug
scenario "N17 ...web.client.DefaultRestClient=debug"     $L.org.springframework.web.client.DefaultRestClient=debug
scenario "N18 ...web.method.HandlerMethod=trace"         $L.org.springframework.web.method.HandlerMethod=trace
scenario "N19 ...jdbc.core.StatementCreatorUtils=trace"  $L.org.springframework.jdbc.core.StatementCreatorUtils=trace
scenario "N20 ...org.hibernate.orm.resource.registry=trace" $L.org.hibernate.orm.resource.registry=trace
scenario "N21 ...org.apache.hc.client5.http.headers=debug" $L.org.apache.hc.client5.http.headers=debug
scenario "N22 ...coyote.http11.Http11InputBuffer=debug"  $L.org.apache.coyote.http11.Http11InputBuffer=debug
scenario "N23 ...coyote.http11.Http11InputBuffer=trace"  $L.org.apache.coyote.http11.Http11InputBuffer=trace
scenario "N24 ...tomcat.util.http.Parameters=debug"      $L.org.apache.tomcat.util.http.Parameters=debug
scenario "N25 org=debug; ...web and org.apache.hc at info" $L.org=debug $L.org.springframework.web=info $L.org.apache.hc=info
scenario "N26 logging.level.ORG.SPRINGFRAMEWORK.WEB=debug" $L.ORG.SPRINGFRAMEWORK.WEB=debug
exit 0
