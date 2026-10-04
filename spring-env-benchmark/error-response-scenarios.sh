#!/bin/bash
# What each error property adds to an HTTP error response, one configuration at a time: the
# reference SCG010 is checked against (VALIDATION.md, "SCG010 error response scenarios").
#
# Each scenario starts one of three apps (separate projects: Spring MVC and WebFlux on Spring Boot
# 4.1.1, Spring MVC on Spring Boot 3.5.16) with the properties as command-line arguments, waits
# until the previous app has released the port and the new one has started, and requests:
#   /boom                       an endpoint that throws IllegalStateException("internal-detail-...")
#   /boom?trace&message         the same, asking for what on-param leaves to the caller
#   /bind?qty=abc               a request parameter that fails binding
#   /bind?qty=abc&errors        the same, asking for the binding errors
# and prints what each response carries: T = stack trace, E = exception class name, M = the
# exception's message, B = binding errors ("-" = none of them). S2 also tries other values of the
# trace parameter. Y1 and Y2 load YAML files written to target/ by this script, for values YAML
# parses itself (unquoted on).
set -u
cd "$(dirname "$0")"
for module in error-response error-response-webflux error-response-boot3; do
    (cd "$module" && mvn -q package -DskipTests) || exit 1
done
LOG=/tmp/scg010-scenario.log
PORT=8093
W=--spring.web.error
S=--server.error

carries() {
    local body
    body=$(curl -s "localhost:$PORT$1" -H 'Accept: application/json')
    local out=""
    grep -q '"trace"' <<< "$body" && out+=T
    grep -q '"exception"' <<< "$body" && out+=E
    grep -q '"message":"internal-detail' <<< "$body" && out+=M
    grep -q '"errors"' <<< "$body" && out+=B
    echo "${out:--}"
}

scenario() {
    local module=$1 name=$2; shift 2
    local waited=0
    while (echo > /dev/tcp/localhost/$PORT) 2>/dev/null; do
        sleep 1
        waited=$((waited + 1))
        [ $waited -lt 60 ] || { echo "port $PORT still in use after 60s" >&2; exit 1; }
    done
    java -jar "$module/target/$module.jar" --server.port=$PORT "$@" > "$LOG" 2>&1 &
    local pid=$!
    for _ in $(seq 1 60); do
        grep -q "Started ErrorApp in\|APPLICATION FAILED" "$LOG" && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    if ! grep -q "Started ErrorApp in" "$LOG"; then
        printf '%-58s app did not start: %s\n' "$name" \
            "$(grep -m1 -E '^ *Reason: ' "$LOG" | sed -E 's/^ *Reason: //; s/org\.springframework\.boot\.autoconfigure\.web\.//g')"
    else
        printf '%-58s boom=%-4s boom?trace&message=%-4s bind=%-4s bind&errors=%s\n' "$name" \
            "$(carries /boom)" "$(carries '/boom?trace&message')" "$(carries '/bind?qty=abc')" "$(carries '/bind?qty=abc&errors')"
        if [ -n "${TRACE_VALUES:-}" ]; then
            local value
            for value in $TRACE_VALUES; do
                printf '%-58s boom?trace=%s carries %s\n' "" "$value" "$(carries "/boom?trace=$value")"
            done
        fi
    fi
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
}

MVC=error-response
echo "== Spring MVC, Spring Boot 4.1.1"
scenario $MVC "D0 defaults"
scenario $MVC "S1 include-stacktrace=always"                $W.include-stacktrace=always
TRACE_VALUES="false FALSE no 0" scenario $MVC "S2 include-stacktrace=on-param" $W.include-stacktrace=on-param
scenario $MVC "S3 include-stacktrace=onParam"               $W.include-stacktrace=onParam
scenario $MVC "S4 include-stacktrace=ON_PARAM"              $W.include-stacktrace=ON_PARAM
scenario $MVC "S5 include-stacktrace=on.param"              $W.include-stacktrace=on.param
scenario $MVC "S6 include-stacktrace=ALWAYS"                $W.include-stacktrace=ALWAYS
scenario $MVC "S7 include-stacktrace=never"                 $W.include-stacktrace=never
scenario $MVC "S8 include-stacktrace= (empty)"              $W.include-stacktrace=
scenario $MVC "S9 include-stacktrace=true"                  $W.include-stacktrace=true
scenario $MVC "S10 include-stacktrace=on"                   $W.include-stacktrace=on
scenario $MVC "S11 include-stacktrace=sometimes"            $W.include-stacktrace=sometimes
scenario $MVC "X1 include-exception=true"                   $W.include-exception=true
scenario $MVC "X2 include-exception=on"                     $W.include-exception=on
scenario $MVC "X3 include-exception=YES"                    $W.include-exception=YES
scenario $MVC "X4 include-exception=1"                      $W.include-exception=1
scenario $MVC "X5 include-exception=false"                  $W.include-exception=false
scenario $MVC "X6 include-exception=always"                 $W.include-exception=always
scenario $MVC "X7 include-exception= (empty)"               $W.include-exception=
scenario $MVC "M1 include-message=always"                   $W.include-message=always
scenario $MVC "M2 include-message=on-param"                 $W.include-message=on-param
scenario $MVC "B1 include-binding-errors=always"            $W.include-binding-errors=always
scenario $MVC "B2 include-binding-errors=on-param"          $W.include-binding-errors=on-param
scenario $MVC "O1 server.error.include-stacktrace=always"   $S.include-stacktrace=always
scenario $MVC "O2 server.error.* all four on"               $S.include-stacktrace=always $S.include-exception=true \
    $S.include-message=always $S.include-binding-errors=always
printf 'spring.web.error:\n  include-exception: on\n' > $MVC/target/unquoted-on.yml
scenario $MVC "Y1 YAML include-exception: on (unquoted)"    --spring.config.additional-location=file:$MVC/target/unquoted-on.yml
printf 'spring.web.error:\n  include-stacktrace: on\n' > $MVC/target/unquoted-on-enum.yml
scenario $MVC "Y2 YAML include-stacktrace: on (unquoted)"   --spring.config.additional-location=file:$MVC/target/unquoted-on-enum.yml

FLUX=error-response-webflux
echo "== WebFlux, Spring Boot 4.1.1"
scenario $FLUX "F0 defaults"
scenario $FLUX "F1 include-stacktrace=always"               $W.include-stacktrace=always
scenario $FLUX "F2 include-stacktrace=on-param"             $W.include-stacktrace=on-param
scenario $FLUX "F3 all four on"                             $W.include-stacktrace=always $W.include-exception=true \
    $W.include-message=always $W.include-binding-errors=always
scenario $FLUX "F4 server.error.* all four on"              $S.include-stacktrace=always $S.include-exception=true \
    $S.include-message=always $S.include-binding-errors=always

BOOT3=error-response-boot3
echo "== Spring MVC, Spring Boot 3.5.16"
scenario $BOOT3 "T0 defaults"
scenario $BOOT3 "T1 server.error.* all four on"             $S.include-stacktrace=always $S.include-exception=true \
    $S.include-message=always $S.include-binding-errors=always
scenario $BOOT3 "T2 server.error.include-stacktrace=on-param" $S.include-stacktrace=on-param
scenario $BOOT3 "T3 spring.web.error.* all four on"         $W.include-stacktrace=always $W.include-exception=true \
    $W.include-message=always $W.include-binding-errors=always
exit 0
