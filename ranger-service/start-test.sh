#!/bin/bash
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#Make sure script has sufficient privileges
# chmod 755 ./start-test.sh

#Run the script
#.bash start-test.sh MAX_ITERATION MAX_CLIENT http(s)://RANGER_ADMIN_HOST:PORT ADMIN_USERNAME ADMIN_PASSWORD 
# bash start-test.sh 1000 5 "http://localhost:6081/" "admin" "rangerR0cks!"

# Read config
source app.conf

WARN="[\e[1;33mWARN\e[0m]"
ERROR="[\e[1;31mERROR\e[0m]"
INFO="[\e[1;34mINFO\e[0m]"

function LOG () {
  echo -e "$1 $2"
}

LOG $INFO "Evaluating script parameter provided"
## Check if max iteration by each client is provided
if [ -z "$1" ]
  then
    LOG $WARN "Max script iteration by each client not supplied using default ($MAX_ITERATION)"
  else
    MAX_ITERATION=$1
fi

# Check if max clients config value is provided
if [ -z "$2" ]
  then
    LOG $WARN "Max python clients not supplied using default ($MAX_CLIENT)"
  else
    MAX_CLIENT=$2
fi

# Check if host is provided
if [ -z "$3" ]
  then
    LOG $WARN "Ranger Admin Host not supplied using default ($ADM_HOSTS)"
  else
    ADM_HOSTS=$3
fi

## Check if username is provided
if [ -z "$4" ]
  then
    LOG $WARN "UserName not supplied using default ($USERNAME)"
  else
    USERNAME=$4
fi

# Check if password is provided
if [ -z "$5" ]
  then
    LOG $WARN "Password not supplied using default ($PASSWORD)"
  else
    PASSWORD=$5
fi

# Remove / from end of $LOG_DIR & append timestamp
SCRIPT_LOG_DIR="${PREFIX_LOG_DIR%/}-$(date +%s)"

# Create log directory if not exist
mkdir -p "$SCRIPT_LOG_DIR"

LOG $INFO "Initiating $MAX_CLIENT concurrent python clients"

idx=1
while [ $idx -le $MAX_CLIENT ]
do
   LOG $INFO "Initiating: 'python ./test.py --startIndex $idx --maxIteration $MAX_ITERATION --incrementBy $MAX_CLIENT --hosts $ADM_HOSTS --username $USERNAME --password $PASSWORD > $SCRIPT_LOG_DIR/script-$(printf "%03d" $idx).log 2>&1 &'"
   python ./test.py --startIndex $idx --maxIteration $MAX_ITERATION --incrementBy $MAX_CLIENT --hosts $ADM_HOST --username $USERNAME --password $PASSWORD > $SCRIPT_LOG_DIR/script-$(printf "%03d" $idx).log 2>&1 &
   idx=`expr $idx + 1`
done

LOG $INFO "$MAX_CLIENT concurrent python clients are initiated successfully."
