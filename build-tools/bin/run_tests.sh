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
    echo "    --skip-security-manager: Skips testing with the security manager"
    echo "    --summary: Print only test summaries"
    exit 1
}

function start_target() {

  if [[ -f /tmp/vuln.log ]]; then
    rm /tmp/vuln.log
  fi

  local jdk_dir=$1
  shift 1

  pushd "${ROOT_DIR}/test" > /dev/null
  ${jdk_dir}/bin/java  -cp log4j-core-2.12.1.jar:log4j-api-2.12.1.jar:. -Dlog4j2.configurationFile=${ROOT_DIR}/src/test/resources/log4j2.properties $* Vuln > /tmp/vuln.log &
  popd > /dev/null

  sleep 2
}

function start_static_target() {

  if [[ -f /tmp/vuln.log ]]; then
    rm /tmp/vuln.log
  fi

  local jdk_dir=$1
  local agent_jar=$2

  pushd "${ROOT_DIR}/test" > /dev/null
  ${jdk_dir}/bin/java  -cp log4j-core-2.12.1.jar:log4j-api-2.12.1.jar:. -Dlog4j2.configurationFile=${ROOT_DIR}/src/test/resources/log4j2.properties -javaagent:${agent_jar} Vuln > /tmp/vuln.log &
  popd > /dev/null
}

function static_agent_configure_verbose() {
  if [ "$3" = "unset" ]; then
    PROP_VALUE=""
  else
    PROP_VALUE="-Dlog4jFixerVerbose=$3"
  fi
  if [ "$4" = "unset" ]; then
    ARG_VALUE=""
  else
    ARG_VALUE="=log4jFixerVerbose=$4"
  fi

  local jdk_dir=$1
  local agent_jar=$2
  pushd "${ROOT_DIR}/test" > /dev/null
  VERBOSE_TEST_OUTPUT=$(${jdk_dir}/bin/java $PROP_VALUE -javaagent:${agent_jar}$ARG_VALUE Vuln 2> /dev/null || true)
  popd > /dev/null
}

function verify_target() {
  local vuln_pid=$1

  # Wait a few seconds for the target to log the patched string
  sleep 3

  kill $vuln_pid

  if grep -q 'Patched JndiLookup' /tmp/vuln.log
  then
    echo "Test passed. Successfully patched target process"
  else
    echo "Test failed. Failed to patch target process"
    cat /tmp/vuln.log
    exit 1
  fi
}

function verify_idempotent_client() {
  if grep -q 'Skipping patch for JVM process' /tmp/client.log
  then
    echo "Test passed. Did not patch already patched target"
  else
    echo "Test failed. Failed or attempted to re-patch target"
    cat /tmp/client.log
    cat /tmp/vuln.log
    exit 1
  fi
}

function verify_idempotent_agent() {
    if grep -q 'hot patch agent already loaded' /tmp/vuln.log
    then
      echo "Test passed. Agent knows it is already loaded"
    else
      echo "Test failed. Agent reloaded itself"
      cat /tmp/client.log
      cat /tmp/vuln.log
      exit 1
    fi
}

if [[ $# -lt 2 ]]; then
    usage
    exit 1
fi

ROOT_DIR="$(pwd)"
# Need fully qualified path
AGENT_JAR=$(readlink -f $1)
JDK_DIR=$2
shift
shift

CLASSNAME="com.amazon.corretto.hotpatch.HotPatchMain"
SKIP_STATIC=""
SKIP_SECURITY_MANAGER=""
while [[ $# -gt 0 ]]; do
    case ${1} in
        --summary)
            set +x
            shift
            ;;
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

case ${JVM_MV} in
    1.7|1.8)
        CLASS_PATH=":${JDK_DIR}/lib/tools.jar"
        ;;
    *)
        CLASS_PATH=""
    ;;
esac

JVM_OPTIONS=""
if [[ "${JVM_MV}" == "17" ]]; then
    JVM_OPTIONS="--add-exports jdk.internal.jvmstat/sun.jvmstat.monitor=ALL-UNNAMED"
fi

pushd "${ROOT_DIR}/test" > /dev/null
${JDK_DIR}/bin/javac -cp log4j-core-2.12.1.jar:log4j-api-2.12.1.jar Vuln.java
popd > /dev/null

echo
echo "******************"
echo "Running JDK${JVM_MV} -> JDK${JVM_MV} Test Idempotent"
echo "------------------"

start_target ${JDK_DIR}
VULN_PID=$!

${JDK_DIR}/bin/java -cp ${AGENT_JAR}${CLASS_PATH} \
${CLASSNAME} $VULN_PID > /tmp/client.log

sleep 1
${JDK_DIR}/bin/java -cp ${AGENT_JAR}${CLASS_PATH} \
${CLASSNAME} $VULN_PID > /tmp/client.log

verify_target $VULN_PID
verify_idempotent_client

echo
echo "******************"
echo "Running JDK${JVM_MV} -> JDK${JVM_MV} Test"
echo "------------------"

start_target ${JDK_DIR}
VULN_PID=$!

${JDK_DIR}/bin/java -cp ${AGENT_JAR}${CLASS_PATH} ${CLASSNAME} $VULN_PID

verify_target $VULN_PID

echo
echo "******************"
echo "Running JDK${JVM_MV} -> JDK${JVM_MV} legacy Log4jHotPatch Test"
echo "------------------"

start_target ${JDK_DIR}
VULN_PID=$!

${JDK_DIR}/bin/java -cp ${AGENT_JAR}${CLASS_PATH} Log4jHotPatch $VULN_PID

verify_target $VULN_PID

if [[ "${JVM_MV}" != "1.7"  && "${JVM_MV}" != "1.8" ]]; then
  echo
  echo "******************"
  echo "Running executable jar JDK${JVM_MV} -> JDK${JVM_MV} Test"
  echo "------------------"

  start_target ${JDK_DIR}
  VULN_PID=$!

  ${JDK_DIR}/bin/java -jar ${AGENT_JAR} $VULN_PID

  verify_target $VULN_PID
fi

if [[ -z "${SKIP_SECURITY_MANAGER}" ]]; then
    echo
    echo "******************"
    echo "Running JDK${JVM_MV} -> JDK${JVM_MV} (Security Manager) Test"
    echo "------------------"

    start_target ${JDK_DIR} -Djava.security.manager -Djava.security.policy=security.policy
    VULN_PID=$!

    ${JDK_DIR}/bin/java ${JVM_OPTIONS} -cp ${AGENT_JAR}${CLASS_PATH} ${CLASSNAME} $VULN_PID

    sleep 1
    ${JDK_DIR}/bin/java ${JVM_OPTIONS} -cp ${AGENT_JAR}${CLASS_PATH} ${CLASSNAME} $VULN_PID

    verify_target $VULN_PID
    verify_idempotent_agent
fi

if [[ -z "${SKIP_STATIC}" ]]; then
    echo
    echo "******************"
    echo "Running AgentMode Verbose Tests"
    echo "------------------"

    function test_static_agent_verbose() {
      static_agent_configure_verbose ${JDK_DIR} ${AGENT_JAR} $1 $2
      local result="true"
      if [ -z "$VERBOSE_TEST_OUTPUT" ]; then
        result="false"
      fi
      printf 'Test verbose config for Prop:%-5s Arg:%-5s Expected:%-5s Output:%-5s\n' "$1" "$2" "$3" "$result"

      if [ "$result" != "$3" ]; then
        echo "Test failed. Unexpected output. Repeating with -x:"
        set -x
        static_agent_configure_verbose ${JDK_DIR} ${AGENT_JAR} $1 $2
        set +x
        exit 1
        fi
    }

    test_static_agent_verbose "unset" "unset" "true"
    test_static_agent_verbose "unset" "true" "true"
    test_static_agent_verbose "unset" "false" "false"
    test_static_agent_verbose "true" "unset" "true"
    test_static_agent_verbose "true" "true" "true"
    test_static_agent_verbose "true" "false" "false"
    test_static_agent_verbose "false" "unset" "false"
    test_static_agent_verbose "false" "true" "true"
    test_static_agent_verbose "false" "false" "false"
    echo "Test passed."

    echo
    echo "******************"
    echo "Running Static JDK${JVM_MV} Test"
    echo "------------------"


    start_static_target ${JDK_DIR} ${AGENT_JAR}
    VULN_PID=$!

    sleep 2

    verify_target $VULN_PID

    echo
    echo "******************"
    echo "Running Static _JAVA_OPTIONS JDK${JVM_MV} Test"
    echo "------------------"


    _JAVA_OPTIONS="-javaagent:${AGENT_JAR}"
    export _JAVA_OPTIONS
    start_target ${JDK_DIR}
    VULN_PID=$!

    sleep 2

    verify_target $VULN_PID
fi
