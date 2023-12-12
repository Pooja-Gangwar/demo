#!/bin/bash
# Conjur Secret Retrieval for CirclCI Orb private-conjur

function main() {
  check_parameter "CONJUR_APPLIANCE_URL" "$PARAM_APPLIANCE_URL"
  check_parameter "CONJUR_ACCOUNT" "$PARAM_ACCOUNT"
  check_parameter "CONJUR_SERVICE_ID" "$PARAM_SERVICE_ID"
  check_parameter "CONJUR_SECRETS_ID" "$PARAM_SECRETS_ID"

  CONJUR_SECRETS_ID="${PARAM_SECRETS_ID}"
  CONJUR_CERTIFICATE="${PARAM_CERTIFICATE}"
  CONJUR_APPLIANCE_URL=$(eval echo "${PARAM_APPLIANCE_URL}")
  CONJUR_ACCOUNT=$(eval echo "${PARAM_ACCOUNT}")
  CONJUR_SERVICE_ID=$(eval echo "${PARAM_SERVICE_ID}")

  if [ -z "${CIRCLE_OIDC_TOKEN_V2}" ]; then
    echo "OIDC Token cannot be found. A CircleCI context must be specified."
    exit 1
  fi

  echo "${CONJUR_CERTIFICATE}" > conjur_"${CONJUR_ACCOUNT}".pem
  echo "::debug Authenticate via Authn-JWT"

  array_secrets
  InstallJq
  authenticate
  fetch_secret
}

function check_parameter() {
  local param_name="$1"
  local param_value="$2"
  if [ -z "$param_value" ]; then
    echo "The $param_name is not found. Please add the $param_name before continuing."
    exit 1
  fi
}

function urlencode() {
    old_lc_collate=$LC_COLLATE
    LC_COLLATE=C

    local length="${#1}"
    for (( i = 0; i < length; i++ )); do
        local c="${1:i:1}"
        case $c in
            [a-zA-Z0-9.~_-]) printf "%s" "$c" ;;
            ' ') printf "%%20" ;;
            *) printf '%%%02X' "'$c" ;;
        esac
    done

    LC_COLLATE=$old_lc_collate
}

function array_secrets() {
    IFS=';'
    read -ra SECRETS <<< "${CONJUR_SECRETS_ID}"
}

function InstallJq() {
    if command -v curl >/dev/null 2>&1 && ! command -v jq >/dev/null 2>&1; then
        uname -a | grep Darwin > /dev/null 2>&1 && JQ_VERSION=jq-osx-amd64 || JQ_VERSION=jq-linux32
        echo "PATH :: $JQ_PATH"
        curl -Ls -o "$JQ_PATH" https://github.com/stedolan/jq/releases/download/jq-1.6/"${JQ_VERSION}"
        chmod +x "$JQ_PATH"
        command -v jq >/dev/null 2>&1
        return $?
    else
        command -v curl >/dev/null 2>&1 || { echo >&2 "CONJUR ORB ERROR: CURL is required. Please install."; exit 1; }
        command -v jq >/dev/null 2>&1 || { echo >&2 "CONJUR ORB ERROR: JQ is required. Please install"; exit 1; }
        return $?
    fi
}

function authenticate(){
  local jwt_token="${CIRCLE_OIDC_TOKEN_V2}"
  local response_code
  ### Fetch Conjur Access Token        
  if [[ -n "${CONJUR_CERTIFICATE}" ]]; then
    echo "::debug Authenticating with certificate"
    response_code=$(curl --cacert "conjur_${CONJUR_ACCOUNT}.pem" -s -w "%{http_code}" -o /tmp/token.txt --request POST "${CONJUR_APPLIANCE_URL}/authn-jwt/${CONJUR_SERVICE_ID}/${CONJUR_ACCOUNT}/authenticate" --header "Content-Type: application/x-www-form-urlencoded" --header "Accept-Encoding: base64" --data-urlencode "jwt=$jwt_token")
  else
    echo "::debug Authenticating without certificate"
    response_code=$(curl -s -w "%{http_code}" -o /tmp/token.txt --request POST "${CONJUR_APPLIANCE_URL}/authn-jwt/${CONJUR_SERVICE_ID}/${CONJUR_ACCOUNT}/authenticate" --header 'Content-Type: application/x-www-form-urlencoded' --header "Accept-Encoding: base64" --data-urlencode "jwt=$jwt_token")
  fi

  if [ "$response_code" != "200" ]; then
    echo "Autentication Failed."
    exit 1
  else 
    echo "Authentication Successful."   
    token=$(cat /tmp/token.txt)
  fi
}

function multiple_secrets_fetch(){
  ##### Batch retrieval of secrets
  if [[ -n "${CONJUR_CERTIFICATE}" ]]; then
    echo "::debug Retrieving multiple secrets with certificate"
    secretsVal=$(curl --cacert "conjur_${CONJUR_ACCOUNT}.pem" -H "Authorization: Token token=\"$token\"" "${CONJUR_APPLIANCE_URL}/secrets?variable_ids=${secrets_string}" | jq -r 'to_entries | map("\(.key)=\(.value)") | join(",")')
  else
    echo "::debug Retrieving multiple secret without certificate"
    secretsVal=$(curl -H "Authorization: Token token=\"$token\"" "${CONJUR_APPLIANCE_URL}/secrets?variable_ids=${secrets_string}" | jq -r 'to_entries | map("\(.key)=\(.value)") | join(",")')
  fi
}

function single_secret_fetch(){
  flag=false
  err_msg="Secret(s) are empty or not found :: "
  for secretId in "${!secretMulti[@]}"; do 
    if [[ -n "${CONJUR_CERTIFICATE}" ]]; then
      echo "::debug Retrieving secret with certificate"
      secretVal=$(curl --cacert "conjur_${CONJUR_ACCOUNT}.pem" -H "Authorization: Token token=\"$token\"" "${CONJUR_APPLIANCE_URL}/secrets/${CONJUR_ACCOUNT}/variable/$secretId")
    else
      echo "::debug Retrieving secret without certificate"
      secretVal=$(curl -H "Authorization: Token token=\"$token\"" "${CONJUR_APPLIANCE_URL}/secrets/${CONJUR_ACCOUNT}/variable/$secretId")
    fi

    if [[ "${secretVal}" == "Malformed authorization token" ]]; then
      echo "::error::Malformed authorization token. Please check your Conjur account, username, and API key. If using authn-jwt, check your Host ID annotations are correct."
      exit 1
    elif [[ "${secretVal}" == *"is empty or not found"* ]]; then
      flag=true
      err_msg+="${secretId}, "
    else 
      echo "export ${secretMulti[$secretId]}=${secretVal}" >> "${BASH_ENV}" # Set environment variable
      echo "Secret fetched successfully.  Environment variable ${secretMulti[$secretId]} set. "
    fi
  done

  if $flag; then
    echo "${err_msg}"
    exit 1
  fi
}

function set_environment_var(){
  multiple_secrets="${secretsVal[0]}" 

  IFS=','
  read -ra comma_split <<< "$multiple_secrets"

  for element in "${comma_split[@]}"; do
    IFS='='
    read -ra equal_split <<< "$element"

    key="${equal_split[0]}"
    value="${equal_split[1]}"

    IFS=':'
    read -ra colon_split <<< "$key" 
    secret_key=$(urlencode "${colon_split[${#colon_split[@]}-1]}")

    if [ "${PARAM_INTEGR}" == "true" ]; then
      echo "Secret fetched successfully. fetched :: $value"
    else  
      echo "export ${secretMulti[$secret_key]}=$value" >> "${BASH_ENV}"
      echo "Secret fetched successfully.  Environment variable ${secretMulti[$secret_key]} set. "
    fi
    IFS=','
  done
  IFS=$' \t\n'
}

function fetch_secret() {
  declare -A secretMulti

  for secret in "${SECRETS[@]}"; do
    IFS='|'
    read -ra METADATA <<< "$secret" 

    if [[ "${#METADATA[@]}" == 2 ]]; then
      secretId=$(urlencode "${METADATA[0]}")
      envVar=${METADATA[1]^^}
    else
      secretId=${METADATA[0]}
      IFS='/'
      read -ra SPLITSECRET <<< "$secretId" 
      arrLength=${#SPLITSECRET[@]} 
      lastIndex=$((arrLength-1)) 
      envVar=${SPLITSECRET[$lastIndex]^^}
      secretId=$(urlencode "${METADATA[0]}")
    fi
    secretMulti["$secretId"]="$envVar" 
  done 

  #### Construct comma-delimited resource IDs of the variables.
  secretsPath=()
  for key in "${!secretMulti[@]}"; do 
    secretsPath+=("${CONJUR_ACCOUNT}"":variable:""$key")
  done

  ### Array of secretsPath into comma separated string
  secrets_string=$(IFS=,; echo "${secretsPath[*]}")

  multiple_secrets_fetch
  #### If Batch retrieval of secrets not found 
  if [[ "${secretsVal}" == *"is empty or not found"* ]]; then
    echo "${secretsVal}. Batch retrieval failed, falling to single secret fetch."
    single_secret_fetch
  else
    echo "Batch retrieval of secrets succeeded."  
    ######set environment variable 
    set_environment_var
  fi
}

TEST_MODE=$(eval echo "${PARAM_TEST_MODE}")

if [ "$TEST_MODE" == "false" ]; then
  main "$@"
fi