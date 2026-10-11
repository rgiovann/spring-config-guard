#!/bin/bash
# The same Spring Boot configuration files run through SCG and through Semgrep's own Spring rules,
# side by side: the measured part of COMPARISON.md ("Semgrep, measured").
#
# Each directory in competitor-comparison/cases/ holds one small configuration (A: Actuator
# exposure, S: secrets). Semgrep runs the rules of its public registry, from semgrep-rules at a
# pinned commit fetched into target/: the four Spring Actuator rules for the A cases, the generic
# secret rules for the S cases. SCG runs with its defaults, from the jar built in the repository
# root. The script prints, per case, Semgrep's rule IDs (file the finding is on) and SCG's rule,
# severity and profile.
#
# Needs Semgrep 1.180.0 (pip install semgrep==1.180.0) and SCG's jar built first:
# mvn -q package -DskipTests in the repository root.
#
# Usage: ./competitor-comparison-scenarios.sh [path to semgrep]   (default: semgrep on the PATH)
set -u
cd "$(dirname "$0")"
SEMGREP=${1:-semgrep}
RULES_COMMIT=9bbf021d0acffa3095fcffd17b2bc7787eb4796d
RULES=competitor-comparison/target/semgrep-rules
JAR=../target/spring-config-guard.jar
CASES=competitor-comparison/cases

[ -f "$JAR" ] || { echo "build SCG first: mvn -q package -DskipTests in the repository root" >&2; exit 1; }
"$SEMGREP" --version > /dev/null 2>&1 || { echo "semgrep not found: pip install semgrep==1.180.0" >&2; exit 1; }

if [ "$(git -C "$RULES" rev-parse HEAD 2>/dev/null)" != "$RULES_COMMIT" ]; then
    rm -rf "$RULES" && mkdir -p "$RULES" && git -C "$RULES" init -q &&
        git -C "$RULES" fetch -q --depth 1 https://github.com/semgrep/semgrep-rules.git "$RULES_COMMIT" &&
        git -C "$RULES" checkout -q FETCH_HEAD || exit 1
fi
SPRING=$RULES/java/spring/security/audit
ACTUATOR_RULES="--config $SPRING/spring-actuator-fully-enabled.yaml --config $SPRING/spring-actuator-fully-enabled-yaml.yaml --config $SPRING/spring-actuator-non-health-enabled.yaml --config $SPRING/spring-actuator-non-health-enabled-yaml.yaml"
SECRET_RULES="--config $RULES/generic/secrets"

semgrep_findings() { # case directory, rule options: "rule@file" per finding, or "-"
    local dir=$1; shift
    SEMGREP_ENABLE_VERSION_CHECK=0 "$SEMGREP" --metrics=off --quiet --json --no-git-ignore "$@" "$dir" 2>/dev/null |
        python3 -c "import json, sys
r = json.load(sys.stdin)['results']
print('; '.join(sorted(x['check_id'].split('.')[-1] + ' (' + x['path'].split('/')[-1] + ':' + str(x['start']['line']) + ')' for x in r)) or '-')"
}

scg_findings() { # case directory: "rule severity [profile]" per finding, or "-"
    java -jar "$JAR" "$1" --json --fail-on=NONE 2>/dev/null |
        python3 -c "import json, sys
r = json.load(sys.stdin)
label = lambda p: 'base' if p == '__spring_config_guard_base__' else p
print('; '.join(sorted(x['ruleId'] + ' ' + x['severity'] + ' [' + label(x['profileLabel']) + ']' for x in r)) or '-')"
}

echo "SCG: $(java -jar "$JAR" --version 2>/dev/null); $("$SEMGREP" --version 2>/dev/null | tail -1 | sed 's/^/Semgrep /'); semgrep-rules ${RULES_COMMIT:0:7}"
for dir in $(ls -d "$CASES"/*/ | sort -V); do
    name=$(basename "$dir")
    case $name in
        A*) rules=$ACTUATOR_RULES ;;
        S*) rules=$SECRET_RULES ;;
    esac
    printf '%-26s semgrep: %s\n%-26s SCG:     %s\n' "$name" "$(semgrep_findings "$dir" $rules)" "" "$(scg_findings "$dir")"
done
