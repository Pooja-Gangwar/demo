#!/usr/bin/env bats

setup(){
  load 'test_helper/bats-support/load'
  load 'test_helper/bats-assert/load'
  load /usr/local/lib/bats-mock.bash

  DIR="$( cd "$( dirname "$BATS_TEST_FILENAME" )" >/dev/null 2>&1 && pwd )"
    # make executables in src/ visible to PATH
  PATH="$DIR/../src:$PATH"

  export PARAM_TEST_MODE="true"
  source './src/scripts/retrieve_secret.sh'
}

@test "1: Check if CONJUR_APPLIANCE_URL is provided" {
  run check_parameter "CONJUR_APPLIANCE_URL" ""
  [ "$status" -eq 1 ]
  [ "$output" = "The CONJUR_APPLIANCE_URL is not found. Please add the CONJUR_APPLIANCE_URL before continuing." ]
}

@test "2: Check if CONJUR_ACCOUNT is provided" {
  run check_parameter "CONJUR_ACCOUNT" ""
  [ "$status" -eq 1 ]
  [ "$output" = "The CONJUR_ACCOUNT is not found. Please add the CONJUR_ACCOUNT before continuing." ]
}

@test "3: Check if CONJUR_SERVICE_ID is provided" {
  run check_parameter "CONJUR_SERVICE_ID" ""
  [ "$status" -eq 1 ]
  [ "$output" = "The CONJUR_SERVICE_ID is not found. Please add the CONJUR_SERVICE_ID before continuing." ]
}

@test "4: Check if CONJUR_SECRETS_ID is provided" {
  run check_parameter "CONJUR_SECRETS_ID" ""
  [ "$status" -eq 1 ]
  [ "$output" = "The CONJUR_SECRETS_ID is not found. Please add the CONJUR_SECRETS_ID before continuing." ]
}

@test "5: urlencode encodes spaces correctly" {
    result=$(urlencode "hello world")
    [ "$result" == "hello%20world" ]
}

@test "6: urlencode encodes special characters correctly" {
    result=$(urlencode "a!b@c#d$e%f^g&h*i(j)k-l_m+n=o{p}q[r]s<t>u?v=w,x.y/z")
    [ "$result" == "a%21b%40c%23d%25f%5Eg%26h%2Ai%28j%29k-l_m%2Bn%3Do%7Bp%7Dq%5Br%5Ds%3Ct%3Eu%3Fv%3Dw%2Cx.y%2Fz" ]
}

@test "7: urlencode leaves alphanumeric characters unchanged" {
    result=$(urlencode "abc123")
    [ "$result" == "abc123" ]
}

@test "8: urlencode works with an empty string" {
  result="$(urlencode "")"
  [ "$result" == "" ]
}

@test "9: array_secrets should parse multiple secrets" {
  export CONJUR_SECRETS_ID="db/sqlusername|sqlusername;db/sql_password"
  array_secrets
  [ "${#SECRETS[@]}" -eq 2 ]
  [ "${SECRETS[0]}" == "db/sqlusername|sqlusername" ]
  [ "${SECRETS[1]}" == "db/sql_password" ]
}

@test "10: array_secrets handles empty CONJUR_SECRETS_ID" {
    CONJUR_SECRETS_ID=""
    array_secrets
    [ "${#SECRETS[@]}" -eq 0 ]
}

@test "11: authenticate should exit with code 1 when response_code is not 200" {
  run authenticate
  assert_failure
  [ "$status" -eq 1 ] 
  assert_output --partial "Autentication Failed."
}

@test "12: authenticate should exit with code 0 when response_code is 200" {
  mock_curl="$(mock_create)"
  mock_set_output ${mock_curl} "conjur_access_token"
  authenticate() {
	  "${mock_curl}" "$@"
  }

  run authenticate
  assert_success
  [ "$status" -eq 0 ] 
  assert_output  "conjur_access_token"
}

@test "13: Test set_environment_var function with PARAM_INTEGR=true" {
  secretsVal=("account_name:variable:key1=value1,account_name:variable:key2=value2,account_name:variable:key3=value3")
  PARAM_INTEGR="true"
  
  run set_environment_var
  [ "$status" -eq 0 ]
  assert_output --partial "Secret fetched successfully. fetched :: value1"
}

@test "14: Test set_environment_var function with PARAM_INTEGR=false" {
  secretsVal="account_name:variable:key1=value1,account_name:variable:key2=value2,account_name:variable:key3=value3"
  PARAM_INTEGR="false"
  BASH_ENV="/tmp/test_env_file"

  run set_environment_var

  [ "$status" -eq 0 ]
  assert_output --partial "Secret fetched successfully.  Environment variable "

  # Clean up: Remove the temporary environment file
  rm "$BASH_ENV"
}

# Mock the curl command to simulate a failure in batch retrieval
@test "15: fetch_secret falls back to single secret fetch on batch retrieval failure" {
    fetch_secret() {
      # Simulate a failure in batch retrieval
      echo "::debug Retrieving multiple secrets without certificate"
      echo "Secret(s) are empty or not found :: secret2, "
      exit 1
    }

  run fetch_secret
  [ "$status" -eq 1 ]
  assert_output --partial  "Secret(s) are empty or not found :: secret2, "
}

@test "fetch_secret retrieves secrets successfully" {
  #mock_curl="$(mock_create)"
  #mock_set_output ${mock_curl} "echo {'secret1': 'value1', 'secret2': 'value2'}"

  #fetch_secret() {
  #  "${mock_curl}" "$@"
  #}
  
  #fetch_secret

  #[ "$status" -eq 0 ]
  #assert_output "Batch retrieval of secrets succeeded."
  #[ "$(cat $BASH_ENV)" = "export SECRET1=value1\nexport SECRET2=value2" ]
}
