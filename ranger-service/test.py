#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License. See accompanying LICENSE file.
#

#!/usr/bin/env python

#Make sure script has sufficient privileges
# chmod 755 ./test.py

#Run the script
# python ./test.py --startIndex START_IDX --maxIteration MAX_ITERATION --incrementBy IDX_INCREMENT_BY --hosts ADMIN_HOST --username USERNAME --password PASSWORD
# python ./test.py --startIndex 1 --maxIteration 10 --incrementBy 5 --hosts "http://localhost:6080" --username "admin" --password "admin123"

import sys
import time
import argparse
import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from datetime import datetime

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Create the parser
my_parser = argparse.ArgumentParser(description='Create, Fetch & Delete Ranger Service')

# Add the arguments
my_parser.add_argument('--hosts',        metavar='ranger-admin-hosts-with-port', type=str, help='Host (including port) of ranger admin', required=True)
my_parser.add_argument('--maxIteration', metavar='maximum-script-iterations',    type=int, help='Maximum number of iterations', required=True)
my_parser.add_argument('--startIndex',   metavar='starting-index-of-script',     type=int, help='Starting index of first iteration', required=True)
my_parser.add_argument('--incrementBy',  metavar='increment-by',                 type=int, help='After each iteration, increment by', required=True)

my_parser.add_argument('--username',    metavar='login-username', type=str, help='UserName of user used to perform test', required=True)
my_parser.add_argument('--password',    metavar='login-password', type=str, help='Password of user used to perform test', required=True)


# Execute the parse_args() method
args = my_parser.parse_args()

session        = requests.Session()
session.auth   = (args.username, args.password)
session.verify = False

session.headers['Accept']       = 'application/json'
session.headers['Content-Type'] = 'application/json'

admin_service_create_url = "{}/service/plugins/services"
admin_service_get_url    = "{}/service/plugins/services/{}"
admin_service_update_url = "{}/service/plugins/services/{}"
admin_service_delete_url = "{}/service/plugins/services/{}"

admin_service_create_data_template = '{"name":"dev_hdfs","displayName":"","description":"HDFS ranger service for DEV","isEnabled":true,"tagService":"","configs":{"username":"admin","password":"rangerR0cks!","fs.default.name":"hdfs://localhost:8020","hadoop.security.authorization":false,"hadoop.security.authentication":"simple","hadoop.security.auth_to_local":"","dfs.datanode.kerberos.principal":"","dfs.namenode.kerberos.principal":"","dfs.secondary.namenode.kerberos.principal":"","hadoop.rpc.protection":"authentication","commonNameForCertificate":"","ranger.plugin.audit.filters":"[{\'accessResult\':\'DENIED\',\'isAudited\':true},{\'actions\':[\'delete\',\'rename\'],\'isAudited\':true},{\'users\':[\'hdfs\'],\'actions\':[\'listStatus\',\'getfileinfo\',\'listCachePools\',\'listCacheDirectives\',\'listCorruptFileBlocks\',\'monitorHealth\',\'rollEditLog\',\'open\'],\'isAudited\':false},{\'users\':[\'oozie\'],\'resources\':{\'path\':{\'values\':[\'/user/oozie/share/lib\'],\'isRecursive\':true}},\'isAudited\':false},{\'users\':[\'spark\'],\'resources\':{\'path\':{\'values\':[\'/user/spark/applicationHistory\'],\'isRecursive\':true}},\'isAudited\':false},{\'users\':[\'hue\'],\'resources\':{\'path\':{\'values\':[\'/user/hue\'],\'isRecursive\':true}},\'isAudited\':false},{\'users\':[\'hbase\'],\'resources\':{\'path\':{\'values\':[\'/hbase\'],\'isRecursive\':true}},\'isAudited\':false},{\'users\':[\'mapred\'],\'resources\':{\'path\':{\'values\':[\'/user/history\'],\'isRecursive\':true}},\'isAudited\':false},{\'actions\':[\'getfileinfo\'],\'isAudited\':false}]"},"type":"hdfs"}'

def log(log_group, message):
   print(str(datetime.now()) + " [" + log_group + "] " + message)

def test_create_service(log_group, service_json, host_idx):
   admin_url = admin_service_create_url.format(admin_host_urls[host_idx])
   log(log_group, " Create service URL: " + str(admin_url))
   resp = session.post(admin_url, data=json.dumps(service_json))

   assert resp.status_code == 200, "Create service request failed"

   service_id   = resp.json()["id"]
   log(log_group, " Created service [ID={}] [name={}]".format(service_id, resp.json()["name"]))

   log(log_group, " Waiting for {} milliseconds".format(wait_between_commands))
   time.sleep(wait_between_commands/1000)
   return service_id

def test_get_service(log_group, service_id, host_idx, flag=True):
   get_service_url = admin_service_get_url.format(admin_host_urls[host_idx], service_id)
   log(log_group, " Get service URL: " + str(get_service_url))
   resp = session.get(get_service_url)

   resp_text = resp.text
   policy_version = -1

   if flag:
      assert resp.status_code == 200, "Get service request failed"
      assert '"id":{}'.format(service_id) in resp_text, resp_text
      policy_version = resp.json()["policyVersion"]
   else:
      assert resp.status_code == 400, "Get service request failed"
      assert not '"id":{}'.format(service_id) in resp_text, resp_text

   return policy_version

def test_update_service(log_group, service_json, service_id, host_idx):
   service_json['description'] = "This is a test service created to test ranger admin service functionality."
   service_json['id'] = service_id
   update_url = admin_service_update_url.format(admin_host_urls[host_idx], service_id)

   log(log_group, " Update service URL: " + str(update_url))
   resp = session.put(update_url, data=json.dumps(service_json))

   assert resp.status_code == 200, "Update service request failed"

   log(log_group, " Waiting for {} milliseconds".format(wait_between_commands))
   time.sleep(wait_between_commands/1000)

def test_delete_service(log_group, service_id, host_idx):
   delete_url = admin_service_delete_url.format(admin_host_urls[host_idx], service_id)

   log(log_group, " Delete service URL: " + str(delete_url))
   resp = session.delete(delete_url)

   assert resp.status_code == 204, "Delete service request failed"

def test_service(log_group, service_json):
   idx = current_cycle
   # Create 
   service_id = test_create_service(log_group + "-CR", service_json, (idx % admin_hosts_count))
   
   # Version check
   service_version_cr_1 = test_get_service(log_group + "-CR", service_id, (idx % admin_hosts_count))
   idx = idx + 1

   if len(admin_host_urls) > 1:
      service_version_cr_2 = test_get_service(log_group + "-CR", service_id, (idx % admin_hosts_count))
      assert service_version_cr_1 == service_version_cr_2, "Policy version must be consistent across admin hosts."

   # Update
   test_update_service(log_group + "-UP", service_json, service_id, (idx % admin_hosts_count))
   
   # Version check
   service_version_up_1 = test_get_service(log_group + "-UP", service_id, (idx % admin_hosts_count))
   idx = idx + 1
   
   if len(admin_host_urls) > 1:
      service_version_up_2 = test_get_service(log_group + "-UP", service_id, (idx % admin_hosts_count))
      assert service_version_up_1 == service_version_up_2, "Policy version must be consistent across admin hosts."

   # Delete
   test_delete_service(log_group + "-DT", service_id, (idx % admin_hosts_count))
   
   service_version_dt_1 = test_get_service(log_group + "-DT", service_id, (idx % admin_hosts_count), False)
   idx = idx + 1

   if len(admin_host_urls) > 1:
      service_version_dt_2 = test_get_service(log_group + "-DT", service_id, (idx % admin_hosts_count), False)
      assert service_version_dt_1 == service_version_dt_2, "Policy version must be consistent across admin hosts."

   log(log_group, "test_service function finished, waiting for {} milliseconds".format(wait_between_commands))
   time.sleep(wait_between_commands/1000)

def get_service_json():
   json_data         = json.loads(admin_service_create_data_template)
   json_data['name'] = "test-{}".format(current_index)

   return json_data

current_index     = args.startIndex
current_cycle     = 1
app_start_time    = time.time()
admin_hosts_list  = args.hosts.split(",")
admin_hosts_count = len(admin_hosts_list)
admin_host_urls   = []

i=0
while i < admin_hosts_count:
   admin_host_urls.append(admin_hosts_list[i].strip().rstrip('/'))
   i += 1

while current_cycle <= args.maxIteration:
   log("CYCLE", "======================== Starting Iteration/ Cycle {} ========================".format(current_cycle))
   wait_between_commands = 200
   wait_between_cycles   = 1000

   # Service
   user_start_time = time.time()
   json_data_user  = get_service_json()

   test_service("SERVICE", json_data_user)

   # Final loop logistics
   log("CYCLE", "<<=== Iteration/ Cycle {} complete. Waiting for {} milliseconds before next Iteration/ Cycle.".format(current_cycle, wait_between_cycles))
   current_index = current_index + args.incrementBy
   current_cycle = current_cycle + 1
   time.sleep(wait_between_cycles/1000)

log("SCRIPT", "##### Overall <<== consumed time = " + str(time.time() - app_start_time) + " seconds.")