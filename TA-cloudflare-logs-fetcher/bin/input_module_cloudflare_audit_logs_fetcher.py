# encoding = utf-8

import os
import sys
import time
import datetime
import requests
from datetime import timedelta
import json
import pickle
import dateutil.parser
# a function that changes permissions and group for a given path location
def setPermissions(location, group='splunkadm', permissions='755'):
    os.system(f'chmod -R {permissions} {location}')
    os.system(f'chgrp -R {group} {location}')        

# convert timestamp to time format
def convert2timeformat(date_time):
    if date_time == "0":
        try:
            formatted_stamp = datetime.datetime.strptime(date_time,"%S").strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception as e:
            sys.stderr.write(str(e))
            sys.exit(1)
    else:
        parsed_input = dateutil.parser.parse(str(date_time))
        try:
            formatted_stamp = datetime.datetime.strptime(date_time,"%Y-%m-%dT%H:%M:%SZ")
            
        except Exception as e:
            formatted_stamp = datetime.datetime.strptime(date_time,"%Y-%m-%dT%H:%M:%S.%fZ")
    
    return formatted_stamp
    
# covert timestamp to epoch time for comparison
def convert2Epoch(date_time):
    parsed_input = dateutil.parser.parse(str(date_time))
        
    formatted_stamp = datetime.datetime.strftime(parsed_input,"%s")
    return formatted_stamp

# find latest scan ID to be used as checkpoint for the program
def findLatestCp(cpFile):
        # check if id cp already exists and read it - if not, create a new one.
    if os.path.exists(cpFile):
        try:
            # try to read the cp
            with open(cpFile, 'rb') as fn:
                return convert2timeformat(pickle.load(fn))
                
        except Exception as e:
            # couldnt read from the cp file. treated as first run.
            init_time_cp = convert2timeformat("0")
            return init_time_cp
            
    else:
        with open(cpFile, 'wb') as fn:
            # dumps the data into the file
            init_time_cp = convert2timeformat("0")
            pickle.dump(init_time_cp, fn)
            return init_time_cp

# compare scan id's; this is used to find new scans to write as new events
def check_timestamp(cp_time, log_time):
    cp_time_epoch = int(convert2Epoch(cp_time))
    log_time_epoch = int(convert2Epoch(log_time))
    
    if cp_time_epoch < log_time_epoch:
        return True
    else:
        return False
        
# check if proxy is enabled; if it is - return proxy settings; else return None.
def getProxy(helper):
    proxy_settings = helper.get_proxy()
    
    try:
        if proxy_settings['proxy_url']: 
            return {"https": f"http://{proxy_settings['proxy_url']}:{proxy_settings['proxy_port']}"}

        else:
            return None
            
    except Exception as e:
        return None


# update checkpoint using a given file name and checkpoint value 
def updateCp(filename,latest_cp):
    # save a checkpoint of latest timestamp fetched from logs
    with open(filename, 'wb') as fn:
        # dumps the data into the file
        pickle.dump(latest_cp, fn)
        

def getAudit(cp_time, helper): 
    # set time parameters
    now = datetime.datetime.now()
    
    # set all needed arguments from user input
    hostname = helper.get_global_setting("hostname")
    org = helper.get_arg("organization")
    url = hostname + "/client/v4/organizations/" + org + "/audit_logs"
    
    auth_email = helper.get_global_setting("x_auth_email")
    auth_key = helper.get_global_setting("x_auth_key")
    
    verify_ssl = helper.get_global_setting("verify_ssl")
    # set proxy settings if enabled; else set None
    proxies = getProxy(helper)
    # set headers for the request
    headers = {
        "X-Auth-Email": auth_email,
        "X-Auth-Key": auth_key,
        "Content-Type": "application/json"
    }
    
    # make HTTP request and return response / errors
    try:
        return requests.get(url, headers=headers, proxies=proxies, verify=verify_ssl).json()

    except Exception as e:
        toLog( str(e) + '\n', log_store_path)
        sys.stderr.write(f"{ str(nowEpoch) } | { str(e) }")
        sys.exit(1)
   
# 
def validate_input(helper, definition):
    """Implement your own validation logic to validate the input stanza configurations"""
    # This example accesses the modular input variable
    # zone_1 = definition.parameters.get('zone_1', None)
    # zone_2 = definition.parameters.get('zone_2', None)
    # zone_3 = definition.parameters.get('zone_3', None)
    # auth_mail = definition.parameters.get('auth_mail', None)
    # auth_password = definition.parameters.get('auth_password', None)
    # local_path = definition.parameters.get('local_path', None)
    pass
 
# this is the main function called by Splunk config to execute the main logic of the program
def collect_events(helper, ew):
    # set local path for app use
    local_path = helper.get_global_setting("local_path")
    setPermissions(local_path)
    
    # check for cp file; if doesnt exist - create and init.
    cp_filename = local_path + 'cp_time_Audit.pk'
    cp_time = findLatestCp(cp_filename)
    
    jsonRes = getAudit(cp_time, helper)
    log_data = jsonRes["result"]
    # iteare logs in log_data
    for log in log_data:
        if check_timestamp(cp_time, log["when"]):
            # write new Splunk event
            new_event = helper.new_event(str(json.dumps(log)), time=None, host=None, index=None, source=None, sourcetype=None, done=True, unbroken=True)
            ew.write_event(new_event)
            
    # set and save updated checkpoint 
    latest_log_time = log_data[0]["when"]
    # save_check_point("cloudflare_security_cp_time", jsonRes["latest_time"])    
    updateCp(cp_filename, latest_log_time)