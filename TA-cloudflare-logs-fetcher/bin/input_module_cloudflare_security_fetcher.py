# encoding = utf-8

import os
import sys
import time
import datetime
import requests
from datetime import timedelta
import json
import pickle

# a function that changes permissions and group for a given path location
def setPermissions(location, group='splunkadm', permissions='755'):
    os.system(f'chmod -R {permissions} {location}')
    os.system(f'chgrp -R {group} {location}')        

# find latest scan ID to be used as checkpoint for the program
def findLatestCp(cpFile):
        # check if id cp already exists and read it - if not, create a new one.
    if os.path.exists(cpFile):
        try:
            # try to read the cp
            with open(cpFile, 'rb') as fn:
                return pickle.load(fn)
        except:
            # couldnt read from the cp file. treated as first run.
            init_time_cp = datetime.datetime.strptime("0","%S")
            return init_time_cp
    else:
        with open(cpFile, 'wb') as fn:
            # dumps the data into the file
            init_time_cp = datetime.datetime.strptime("0","%S")
            pickle.dump(init_time_cp, fn)
            return init_time_cp


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
        

def getFirewallAudit(cp_time, helper): 
    # set time parameters
    now = datetime.datetime.now()
    # get cp_time 
    since_time = datetime.datetime.strftime(cp_time, "%Y-%m-%dT%H:%M:%SZ")
    to_time = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    
    # set all needed arguments from user input
    hostname = helper.get_global_setting("hostname")
    url = hostname + "/client/v4/graphql/"
    
    auth_email = helper.get_global_setting("x_auth_email")
    auth_key = helper.get_global_setting("x_auth_key")
    
    verify_ssl = helper.get_global_setting("verify_ssl")
    
    zone = helper.get_arg("zone_id")
    # set limit parameter for request as int type
    try:
        limit = int(helper.get_arg("limit"))
        
    except Exception as e:
        sys.stderr.write(str(e))
        sys.exit(1)
        
    # set proxy settings if enabled; else set None
    proxies = getProxy(helper)
    # set headers for the request
    headers = {
        "X-Auth-Email": auth_email,
        "X-Auth-Key": auth_key,
        "Content-Type": "application/json"
    }
    # Query the raw firewall events
    body = {'query': '''{	
	  viewer {
        zones(filter: {zoneTag: $zone_tag}) {
          firewallEventsAdaptive(limit: $results_limit, orderBy: [datetime_ASC], filter: $filter)  
			{
			action
			clientASNDescription
			clientAsn
			clientCountryName
			clientIP
			clientIPClass
			clientRefererHost
			clientRefererPath
			clientRefererQuery
			clientRefererScheme
			clientRequestHTTPHost
			clientRequestHTTPMethodName
			clientRequestHTTPProtocol
			clientRequestPath
			clientRequestQuery
			clientRequestScheme
			datetime				
			edgeColoName
			edgeResponseStatus
			kind
			originResponseStatus
			originatorRayName
			rayName
			ruleId
			sampleInterval
			source
			userAgent			
			}
        }
      }
    }''',
	'variables': {
		'zone_tag': zone,
		'results_limit': limit,
		'filter': {
			'datetime_gt': since_time,
			'datetime_leq': to_time
			}
		}
	}	

    try:
        # make HTTP request & post query data in & get response in JSON
        response = requests.post(url, headers=headers, proxies=proxies, json=body, verify=verify_ssl).json()
        # return response to main function
        res_data = {
            "res": response,
            "latest_time": to_time
            }

        return res_data
        
    except Exception as e:
        sys.stderr.write(str((e)))
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
    cp_filename = local_path + 'cp_time_securityAudit.pk'
    cp_time = findLatestCp(cp_filename)
    
    jsonRes = getFirewallAudit(cp_time, helper)
    
    if jsonRes["res"]["errors"] != None:
        for error in jsonRes["res"]["errors"]:
            sys.stderr.write(str(json.dumps(error)))
        sys.exit(1)
    else:
        log_data = jsonRes["res"]["data"]["viewer"]["zones"][0]["firewallEventsAdaptive"]
        log_count = len(log_data)
        
        for log in log_data:
            log = json.dumps(log)
            # write new Splunk event
            new_event = helper.new_event(str(log), time=None, host=None, index=None, source=None, sourcetype=None, done=True, unbroken=True)
            ew.write_event(new_log)
    
    # save_check_point("cloudflare_security_cp_time", jsonRes["latest_time"])    
    updateCp(cp_filename, jsonRes["latest_time"])