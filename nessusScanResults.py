#!/usr/bin/env python3

import sys,os,getopt
import traceback
import io
import os
import fcntl
import json
import time
import csv
import requests
from random import randrange
from datetime import datetime

from six import PY2

if PY2:
    get_unicode_string = unicode
else:
    get_unicode_string = str


import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, './ds-integration')
from DefenseStorm import DefenseStorm

class integration(object):

    payload = {
        "format": "csv",
        "reportContents": {
            "csvColumns": {
                "id": True,
                "cve": True,
                "cvss": True,
                "risk": True,
                "hostname": True,
                "protocol": True,
                "port": True,
                "plugin_name": True,
                "synopsis": True,
                "description": True,
                "solution": True,
                "see_also": True,
                "plugin_output": False,
                "stig_severity": True,
                "cvss3_base_score": True,
                "cvss_temporal_score": True,
                "cvss3_temporal_score": True,
                "risk_factor": True,
                "references": True,
                "plugin_information": True,
                "exploitable_with": True
            }
        },
        "extraFilters": {
            "host_ids": [],
            "plugin_ids": []
        }
    }


    def get_token(self):
        token_url = self.url + "/session"
        TOKENPARAMS = {'username':self.user, 'password':self.password}
        try:
            r = requests.post(url = token_url, data = TOKENPARAMS, verify = False)
        except Exception as e:
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return None
        if not r or r.status_code != 200:
            self.ds.log('WARNING',
                    "Received unexpected " + str(r) + " response from Cb Defense Server {0}.".format(
                    token_url))
            return None
        try:
            jsonData = r.json()
            token = str("token="+jsonData['token'])
            return token
        except Exception as e:
                traceback.print_exc()
                self.ds.log("ERROR", "Failed to get token")
                self.ds.log('ERROR', "Exception {0}".format(str(e)))

    def get_folders(self):
        URL=self.url+"/folders"
        try:
            t = requests.get(url = URL, headers=self.headers, verify = False)
        except Exception as e:
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return None
        if not t or t.status_code != 200:
            self.ds.log('WARNING',
                    "Received unexpected " + str(t) + " response from Cb Defense Server {0}.".format(
                    URL))
            return None
        jsonFolder = t.json()
        return jsonFolder['folders']

    def get_scan_list(self, folder_id):
        # Look for scans from upToThisManyDaysAgo from GET /scans request
        epochTime = time.time()
        splitDay = str(self.last_run).split('.',-1)
        URL = self.url + "/scans?folder_id=" + folder_id + "&last_modification_date=" +splitDay[0]
        try:
            t = requests.get(url = URL, headers=self.headers, verify = False)
        except Exception as e:
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return None
        if not t or t.status_code != 200:
            self.ds.log('WARNING',
                    "Received unexpected " + str(t) + " response from Cb Defense Server {0}.".format(
                    URL))
            return None
        data = t.json()
        return data['scans']

    def get_scan(self, scan_id, outfile, out_format = 'nessus'):

        outfile = outfile + '.' + out_format
        URL = self.url + "/scans/" + str(scan_id) + "/export"
        this_payload = self.payload
        this_payload['format'] = out_format
        try:
            r = requests.post(url = URL, headers=self.headers, data = json.dumps(self.payload), verify = False)
        except Exception as e:
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return None
        if not r or r.status_code != 200:
            self.ds.log('WARNING',
                    "Received unexpected " + str(r) + " response from Cb Defense Server {0}.".format(
                    URL))
            return None

        jsonData = r.json()
        scanFile = str(jsonData['file'])
        scanToken = str(jsonData['token'])
        status = "loading"
        while status != 'ready':
            URL = self.url + "/scans/" +str(scan_id) + "/export/" + scanFile + "/status"
            try:
                t = requests.get(url = URL, headers=self.headers, verify = False)
            except Exception as e:
                self.ds.log('ERROR', "Exception {0}".format(str(e)))
                return None
            if not t or t.status_code != 200:
                self.ds.log('WARNING',
                    "Received unexpected " + str(t) + " response from Cb Defense Server {0}.".format(
                    URL))
                return None
            data = t.json()
            if data['status'] == 'ready':
                status = data['status']
            else:
                time.sleep(int(self.sleep_period))
        URL = self.url + "/scans/" + str(scan_id) + "/export/" + scanFile + "/download"
        try:
            d = requests.get(url = URL, headers=self.headers, verify = False)
        except Exception as e:
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return None
        if not d or d.status_code != 200:
            self.ds.log('WARNING',
                    "Received unexpected " + str(d) + " response from Cb Defense Server {0}.".format(
                    URL))
            return None
        f = open(outfile, 'wb').write(d.content)

    def get_scan_download_list(self, folders):
        scan_download_list = []
        for folder in folders:
            for item in self.scan_list:
                if item['folder'] == folder['name']:
                    scan_list = self.get_scan_list(str(folder['id']))
                    if scan_list != None:
                        for scan in scan_list:
                            if scan['status'] == 'completed':
                                scan_download_list.append({'folder': folder['name'], 'id':scan['id'], 'name':scan['name'], 'last_modification_date':scan['last_modification_date']})
                                self.ds.log("INFO", "Collecting Scans from folder " + folder['name'] + '(' + str(folder['id']) + '): ' + scan['name'] + '(' + str(scan['id']) + ') - ' + (datetime.utcfromtimestamp(int(scan['last_modification_date']))).strftime('%Y-%m-%d %H%M%S'))
                    else:
                        self.ds.log("INFO", "Collecting Scans from folder " + folder['name'] + '(' + str(folder['id']) + '): ' + 'None')
        return scan_download_list


    def get_scans_list(self, filename):
        try:
            with open(filename) as json_file:
                    scan_list = json.load(json_file)
        except Exception as e:
            traceback.print_exc()
            self.ds.log("ERROR", "Failed to load db_json_file + " + filename)
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
        return scan_list


    def send_scan_to_grid(self, filename, scan_time):
        event_list = []
        with open(filename, 'r') as f:
            dicted = csv.DictReader(f)
            vulns = list(dicted)
            for entry in vulns:
                for key in entry:
                    if entry[key] == "":
                        entry[key] = "None"
                entry['message'] = 'Scan Result - ' + entry['Synopsis']
                entry['scanner'] = self.scanner
                entry['timestamp'] = scan_time
                #entry['hostname'] = entry['host']
                self.ds.writeJSONEvent(entry, flatten = False)

    def nessus_main(self): 

        # Get JDBC Config info
        try:
            self.user = self.ds.config_get('nessus', 'user')
            self.password = self.ds.config_get('nessus', 'password')
            self.scanner = self.ds.config_get('nessus', 'scanner')
            self.state_dir = self.ds.config_get('nessus', 'state_dir')
            self.scan_list_file = self.ds.config_get('nessus', 'scan_list')
            self.sleep_period = self.ds.config_get('nessus', 'sleep_period')
            self.days_ago = self.ds.config_get('nessus', 'days_ago')
            self.last_run = self.ds.get_state(self.state_dir)
            self.url = "https://" + self.scanner + ":8834"
            self.token = self.get_token()
            if self.token == None:
                self.ds.log('ERROR', "Failed to get token")
                return

            self.headers = {'X-Cookie': self.token, 'Content-type': 'application/json', 'Accept': 'text/plain'}
            self.time_format = "%Y-%m-%d %H:%M:%S"

            current_time = time.time()

            if self.last_run == None:
                self.ds.log("INFO", "No previous state.  Collecting logs for last " + str(self.days_ago) + " days")
                #self.last_run = (datetime.utcfromtimestamp((current_time - ( 60 * 60 * 24 * int(self.days_ago))))).strftime(self.time_format)
                self.last_run = current_time - ( 60 * 60 * 24 * int(self.days_ago))
            self.current_run = current_time
        except Exception as e:
                traceback.print_exc()
                self.ds.log("ERROR", "Failed to get required configurations")
                self.ds.log('ERROR', "Exception {0}".format(str(e)))


        self.scan_list = self.get_scans_list(self.scan_list_file)
        folders = self.get_folders()
        if folders == None:
            self.ds.log('ERROR', "No folders found")
            return
        self.scan_download_list = self.get_scan_download_list(folders)


        for scan in self.scan_download_list:
            scan_time = (datetime.utcfromtimestamp(int(scan['last_modification_date']))).strftime('%Y-%m-%dT%H:%M:%S') + 'Z'
            filename = scan['folder'] + '-' + scan['name'] + '-' + scan_time
            self.get_scan(scan_id = scan['id'], outfile=filename.replace(' ', '_'), out_format='nessus')
            self.get_scan(scan_id = scan['id'], outfile=filename.replace(' ', '_'), out_format='csv')

            self.send_scan_to_grid(filename=filename.replace(' ', '_')+".csv", scan_time = scan_time)


        self.ds.set_state(self.state_dir, self.current_run)
        self.ds.log('INFO', "Done Sending Notifications")


    def run(self):
        try:
            pid_file = self.ds.config_get('nessus', 'pid_file')
            fp = io.open(pid_file, 'w')
            try:
                fcntl.lockf(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except IOError:
                self.ds.log('ERROR', "An instance of this integration is already running")
                # another instance is running
                sys.exit(0)
            self.nessus_main()
        except Exception as e:
            traceback.print_exc()
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return
    
    def usage(self):
        print
        print (os.path.basename(__file__))
        print
        print ('  No Options: Run a normal cycle')
        print
        print ('  -t    Testing mode.  Do all the work but do not send events to GRID via ')
        print ('        syslog Local7.  Instead write the events to file \'output.TIMESTAMP\'')
        print ('        in the current directory')
        print
        print ('  -l    Log to stdout instead of syslog Local6')
        print
        print ('  -a    Generate a .csv file that can be used for Asset Import in Grid')
        print
    
    def __init__(self, argv):

        self.testing = False
        self.send_syslog = True
        self.ds = None
        self.conf_file = None
        self.conn_url = None
        self.gen_assets_file = False
    
        try:
            opts, args = getopt.getopt(argv,"htnlac:",["datedir="])
        except getopt.GetoptError:
            self.usage()
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                self.usage()
                sys.exit()
            elif opt in ("-t"):
                self.testing = True
            elif opt in ("-l"):
                self.send_syslog = False
            elif opt in ("-c"):
                self.conf_file = arg
            elif opt in ("-a"):
                self.gen_assets_file = True
    
        try:
            self.ds = DefenseStorm('nessusScanResults', testing=self.testing, send_syslog = self.send_syslog, config_file = self.conf_file)
        except Exception as e:
            traceback.print_exc()
            try:
                self.ds.log('ERROR', 'ERROR: ' + str(e))
            except:
                pass


if __name__ == "__main__":
    i = integration(sys.argv[1:]) 
    i.run()
