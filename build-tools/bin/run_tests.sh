#!/bin/bash

set -x
set -o nounset
set -e

function usage() {
    set +x
    echo "Runs tests for the hotpatch agent."
    echo "Usage: run_tests.sh <Path to agent.jar> <JDK_ROOT>"
    echo "Optional params:"
    echo "    --classname <name of main class>:"
    echo "    --skip-static:  Skips tests of the static agent"
    echo "    --skip-security-manager: Skips testing with the securit manager"
    exit 1
}

function start_target() {

  if [[ -f /tmp/vuln.log ]]; then
    rm /tmp/vuln.log
  fi

  local jdk_dir=$1
  shift 1

  pushd "${ROOT_PATH}/test"
  ${jdk_dir}/bin/javac -cp log4jrce-piped.jar Vuln.java
  pwd
  ${jdk_dir}/bin/java  -cp log4jrce-piped.jar:. $* Vuln > /tmp/vuln.log &
  popd

  sleep 2
}

function start_static_target() {

  if [[ -f /tmp/vuln.log ]]; then
    rm /tmp/vuln.log
  fi

  local jdk_dir=$1
  local agent_jar=$2

  pushd "${ROOT_PATH}/test"
  ${jdk_dir}/bin/javac -cp log4jrce-piped.jar Vuln.java
  ${jdk_dir}/bin/java  -cp log4jrce-piped.jar:. -javaagent:${agent_jar} Vuln > /tmp/vuln.log &
  popd
}

function verify_target() {
  local vuln_pid=$1

  # Wait a few seconds for the target to log the patched string
  sleep 3

  kill $vuln_pid

  if grep -q 'Patched JndiLookup' /tmp/vuln.log
  then
    echo "Successfully patched target process"
  else
    echo "Failed to patch target process"
    cat /tmp/vuln.log
    exit 1
  fi
}

function verify_idempotent_client() {
  if grep -q 'Skipping patch for JVM process' /tmp/client.log
  then
    echo "Did not patch already patched target"
  else
    echo "Failed or attempted to re-patch target"
    cat /tmp/client.log
    cat /tmp/vuln.log
    exit 1
  fi
}

function verify_idempotent_agent() {
    if grep -q 'hot patch agent already loaded' /tmp/vuln.log
    then
      echo "Agent knows it is already loaded"
    else
      echo "Agent reloaded itself"
      cat /tmp/client.log
      cat /tmp/vuln.log
      exit 1
    fi
}

if [[ $# -lt 2 ]]; then
    usage
    exit 1
fi

ROOT_PATH="$(pwd)"
# Need fully qualified path
AGENT_JAR=$(realpath $1)
JDK_DIR=$2
shift
shift

CLASSNAME="Log4jHotPatch17"
SKIP_STATIC=""
SKIP_SECURITY_MANAGER=""
while [[ $# -gt 0 ]]; do
    case ${1} in
        --classname)
            CLASSNAME=${2}
            shift
            shift
            ;;
        --skip-static)
            SKIP_STATIC=1
            shift
            ;;
        --skip-security-manager)
            SKIP_SECURITY_MANAGER=1
            shift
            ;;
        * )
            echo "Unknown option '${1}'"
            usage
            ;;
    esac
done

JVM_MV=$(${JDK_DIR}/bin/java -XshowSettings:properties -version 2>&1 |grep java.vm.specification.version | cut -d'=' -f2 | tr -d ' ')

CLASS_PATH=""
if [[ "${JVM_MV}" == "1.8" ]]; then
    CLASS_PATH=":${JDK_DIR}/lib/tools.jar"
fi

JVM_OPTIONS=""
if [[ "${JVM_MV}" == "17" ]]; then
    JVM_OPTIONS="--add-exports jdk.internal.jvmstat/sun.jvmstat.monitor=ALL-UNNAMED"
fi

echo "******************"
echo "Running JDK${JVM_MV} -> JDK${JVM_MV} Test Idempotent"

start_target ${JDK_DIR}
VULN_PID=$!

${JDK_DIR}/bin/java -cp ${AGENT_JAR}${CLASS_PATH} \
${CLASSNAME} $VULN_PID > /tmp/client.log

sleep 1
${JDK_DIR}/bin/java -cp ${AGENT_JAR}${CLASS_PATH} \
${CLASSNAME} $VULN_PID > /tmp/client.log

verify_target $VULN_PID
verify_idempotent_client

echo "******************"
echo "Running JDK${JVM_MV} -> JDK${JVM_MV} Test"
start_target ${JDK_DIR}
VULN_PID=$!

${JDK_DIR}/bin/java -cp ${AGENT_JAR}${CLASS_PATH} ${CLASSNAME} $VULN_PID

verify_target $VULN_PID

if [[ -z "${SKIP_SECURITY_MANAGER}" ]]; then
    echo "******************"
    echo "Running JDK${JVM_MV} -> JDK${JVM_MV} (Security Manager) Test"
    start_target ${JDK_DIR} -Djava.security.manager -Djava.security.policy=security.policy
    VULN_PID=$!

    ${JDK_DIR}/bin/java ${JVM_OPTIONS} -cp ${AGENT_JAR}${CLASS_PATH} ${CLASSNAME} $VULN_PID

    sleep 1
    ${JDK_DIR}/bin/java ${JVM_OPTIONS} -cp ${AGENT_JAR}${CLASS_PATH} ${CLASSNAME} $VULN_PID

    verify_target $VULN_PID
    verify_idempotent_agent
fi

if [[ -z "${SKIP_STATIC}" ]]; then
    echo "******************"
    echo "Running Static JDK${JVM_MV} Test"

    start_static_target ${JDK_DIR} ${AGENT_JAR}
    VULN_PID=$!

    sleep 2

    verify_target $VULN_PID

    echo "******************"
    echo "Running Static _JAVA_OPTIONS JDK${JVM_MV} Test"

    _JAVA_OPTIONS="-javaagent:${AGENT_JAR}"
    export _JAVA_OPTIONS
    start_target ${JDK_DIR}
    VULN_PID=$!

    sleep 2

    verify_target $VULN_PID
fi