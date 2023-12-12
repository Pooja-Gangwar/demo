#!/bin/bash
set -exo pipefail

declare DOCKER_COMPOSE_ARGS 

TARGET="${PARAM_TARGET}"  # can also be set to 'enterprise'

export CONJUR_DATA_KEY='iFra75qdvsLENSV+qXYFMkv7KJS3t+82Po4mmjZLxZc='

CONJUR_ACCOUNT='myaccount'
CONJUR_AUTHN_PASSWORD='SEcret12!!!!'

# These variables are set after configuring conjur
api_key=""
ssl_cert=""

function finish() {
  case "$TARGET" in
    "oss"|"enterprise")
  if [[ -z "$KEEP_CONTAINERS" ]]; then
    echo "> Terminating local Conjur environment"
    dockerCompose down -v
  else
    echo "> KEEP_CONTAINERS is set, not terminating local Conjur environment"
  fi
 ;;
 esac

}

trap finish EXIT

# shellcheck disable=SC2086
function dockerCompose() {
  docker compose $DOCKER_COMPOSE_ARGS "$@"
}

function conjurExec() {
  if [[ "$TARGET" == "oss" ]]; then
    dockerCompose exec -T conjur "$@"
  else
    dockerCompose exec -T conjur-server "$@"
  fi
}

function clientExec() {
  dockerCompose exec -T client "$@"
}

function main() {
  checkTarget
  case "$TARGET" in
  "oss"| "enterprise")
  launchConjur
  configureConjur
  ;;
  esac
  runFetchConjur
}

function checkTarget() {
  case "$TARGET" in
  "oss")
    export DOCKER_COMPOSE_ARGS="-f docker-compose.oss.yml -f docker-compose.yml"
    export CONJUR_WAIT_COMMAND="conjurctl wait"
    ;;
  "enterprise")
    export DOCKER_COMPOSE_ARGS="-f docker-compose.enterprise.yml -f docker-compose.yml"
    export CONJUR_WAIT_COMMAND="/opt/conjur/evoke/bin/wait_for_conjur"
    ;;
    "cloud")
    ;;
  *)
    echo "> '$TARGET' is not a supported target"
    exit 1
    ;;
  esac
}

function launchConjur() {
  echo "> Launching local Conjur environment"
   echo "> TARGET set to :: ${TARGET}"

  echo ">> Pulling images (this may take a long time)"
  dockerCompose pull -q

  echo ">> Starting Conjur/DAP server"
  dockerCompose up -d conjur-server
  echo ">> Creating account '$CONJUR_ACCOUNT'"
  if [[ "$TARGET" == "enterprise" ]]; then
    conjurExec evoke configure master \
      --accept-eula \
      -h conjur-server \
      -p "$CONJUR_AUTHN_PASSWORD" \
      "$CONJUR_ACCOUNT"
  else
    # We need to wait for Conjur OSS to establish a DB connection before
    # attempting to create the account
    conjurExec $CONJUR_WAIT_COMMAND
    conjurExec conjurctl account create "$CONJUR_ACCOUNT"
  fi

  echo ">> Waiting on conjur..."
  conjurExec $CONJUR_WAIT_COMMAND
}

function configureConjur() {
  echo "> Configuring local Conjur environment"

  export CONJUR_APPLIANCE_URL=https://conjur-server
  export CONJUR_ACCOUNT="$CONJUR_ACCOUNT"
  export CONJUR_AUTHN_LOGIN="admin"

  if [[ "$TARGET" == "enterprise" ]]; then
    ssl_cert=$(conjurExec cat /opt/conjur/etc/ssl/conjur.pem)
  else
    ssl_cert=$(cat "test/https_config/ca.crt")
  fi
  export CONJUR_SSL_CERTIFICATE="$ssl_cert"

  echo "$ssl_cert" > "test/conjur.pem"

  if [[ "$TARGET" == "oss" ]]; then
    api_key=$(conjurExec conjurctl role retrieve-key \
      "$CONJUR_ACCOUNT:user:admin" | tr -d '\r')
    export CONJUR_AUTHN_API_KEY="$api_key"
  fi

  echo ">> Starting CLI"
  dockerCompose up -d client

  if [[ "$TARGET" == "enterprise" ]]; then
    echo ">> Logging in CLI to the server"
    clientExec conjur authn login -u admin -p "$CONJUR_AUTHN_PASSWORD"
    api_key=$(clientExec conjur user rotate_api_key)
    export CONJUR_AUTHN_API_KEY="$api_key"
  fi

  echo ">> Applying policies"

  # Policy files are mounted in docker-compose
  clientExec conjur policy load --replace root policy/base.yml
  clientExec conjur policy load data/circleci policy/authn-host-circleci.yml
  clientExec conjur policy load root policy/authn-jwt-circleci.yml
  clientExec conjur list
  clientExec conjur variable values add conjur/authn-jwt/circleci1/jwks-uri "https://oidc.circleci.com/org/56ee901c-258a-4318-9e77-a59fa0c6b976/.well-known/jwks-pub.json"
  clientExec conjur variable values add conjur/authn-jwt/circleci1/issuer "https://oidc.circleci.com/org/56ee901c-258a-4318-9e77-a59fa0c6b976"
  clientExec conjur variable values add conjur/authn-jwt/circleci1/audience "56ee901c-258a-4318-9e77-a59fa0c6b976"
  clientExec conjur variable values add conjur/authn-jwt/circleci1/identity-path "data/circleci/apps"
  clientExec conjur variable values add conjur/authn-jwt/circleci1/token-app-property "oidc.circleci.com/project-id"
  clientExec conjur variable values add data/circleci/apps/safe/secret1 SECRETXcLhn23MJcimV
  clientExec conjur variable values add data/circleci/apps/safe/secret2 '&&@~`)^%#:"":" SECRETX@#@$#@%$@%$@'
}

function runFetchConjur() {
    case "$TARGET" in
    "oss"| "enterprise")
      export PARAM_APPLIANCE_URL='https://conjur-server'
      export PARAM_SERVICE_ID='circleci1'
      export PARAM_CERTIFICATE=$CONJUR_SSL_CERTIFICATE
      export PARAM_ACCOUNT='myaccount'
      export PARAM_SECRETS_ID="data/circleci/apps/safe/secret1;data/circleci/apps/safe/secret2"
    ;;
    *)
    # Conjur configuration parameters
      export PARAM_APPLIANCE_URL='https://conjurcloudint.secretsmgr.cyberark.cloud/api'
      export PARAM_SERVICE_ID='circleci1'
      export PARAM_ACCOUNT='conjur'
      export PARAM_SECRETS_ID="data/circleci/apps/safe/secret1;data/circleci/apps/safe/secret2"
      export PARAM_TEST_MODE="false"
      export PARAM_INTEGR="true"
    ;;
    esac

    docker compose -f docker-compose.yml build circleci-orb
    docker compose -f docker-compose.yml run circleci-orb 
    docker compose rm --force \
      --stop \
      -v \
      circleci-orb
}
main