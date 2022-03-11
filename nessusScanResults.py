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
import zipfile

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


    def get_token(self, scanner):
        url = "https://" + scanner + ":8834"
        token_url = url + "/session"
        TOKENPARAMS = {'username':self.user, 'password':self.password}
        try:
            r = requests.post(url = token_url, data = TOKENPARAMS, verify = False)
        except Exception as e:
            self.ds.logger.error("Exception {0}".format(str(e)))
            return None
        if not r or r.status_code != 200:
            self.ds.logger.warning(
                    "Received unexpected " + str(r) + " response from Nessus Server {0}.".format(
                    token_url))
            return None
        try:
            jsonData = r.json()
            token = str("token="+jsonData['token'])
            return token
        except Exception as e:
                self.ds.logger.error("Failed to get token")
                self.ds.logger.error("Exception {0}".format(str(e)))
                self.ds.logger.error("%s" %(traceback.format_exc().replace('\n',';')))


    def get_folders(self, scanner):
        URL = "https://" + scanner + ":8834" + '/folders'
        try:
            t = requests.get(url = URL, headers=self.headers, verify = False)
        except Exception as e:
            self.ds.logger.error("Exception {0}".format(str(e)))
            return None
        if not t or t.status_code != 200:
            self.ds.logger.warning(
                    "Received unexpected " + str(t) + " response from Nessus Server {0}.".format(
                    URL))
            return None
        jsonFolder = t.json()
        self.ds.logger.info('Folders: ' + str(jsonFolder))
        return jsonFolder['folders']

    def get_scan_list(self, scanner, folder_id):
        # Look for scans from upToThisManyDaysAgo from GET /scans request
        epochTime = time.time()
        splitDay = str(self.last_run).split('.',-1)
        URL = "https://" + scanner + ":8834" + "/scans?folder_id=" + folder_id + "&last_modification_date=" +splitDay[0]
        try:
            t = requests.get(url = URL, headers=self.headers, verify = False)
        except Exception as e:
            self.ds.logger.error("Exception {0}".format(str(e)))
            return None
        if not t or t.status_code != 200:
            self.ds.logger.warning(
                    "Received unexpected " + str(t) + " response from Nessus Server {0}.".format(
                    URL))
            return None
        data = t.json()
        return data['scans']

    def get_scan(self, scanner, scan_id, outfile, out_format = 'nessus'):

        outfile = outfile + '.' + out_format
        URL = "https://" + scanner + ":8834" + "/scans/" + str(scan_id) + "/export"
        this_payload = self.payload
        this_payload['format'] = out_format
        try:
            r = requests.post(url = URL, headers=self.headers, data = json.dumps(self.payload), verify = False)
        except Exception as e:
            self.ds.logger.error("Exception {0}".format(str(e)))
            return None
        if not r or r.status_code != 200:
            self.ds.logger.warning(
                    "Received unexpected " + str(r) + " response from Nessus Server {0}.".format(
                    URL))
            return None

        jsonData = r.json()
        scanFile = str(jsonData['file'])
        scanToken = str(jsonData['token'])
        status = "loading"
        while status != 'ready':
            URL = "https://" + scanner + ":8834" + "/scans/" +str(scan_id) + "/export/" + scanFile + "/status"
            try:
                t = requests.get(url = URL, headers=self.headers, verify = False)
            except Exception as e:
                self.ds.logger.error("Exception {0}".format(str(e)))
                return None
            if not t or t.status_code != 200:
                self.ds.logger.warning(
                    "Received unexpected " + str(t) + " response from Nessus Server {0}.".format(
                    URL))
                return None
            data = t.json()
            if data['status'] == 'ready':
                status = data['status']
            else:
                time.sleep(int(self.sleep_period))
        URL = "https://" + scanner + ":8834" + "/scans/" + str(scan_id) + "/export/" + scanFile + "/download"
        try:
            d = requests.get(url = URL, headers=self.headers, verify = False)
        except Exception as e:
            self.ds.logger.error("Exception {0}".format(str(e)))
            return None
        if not d or d.status_code != 200:
            self.ds.logger.warning(
                    "Received unexpected " + str(d) + " response from Nessus Server {0}.".format(
                    URL))
            return None
        f = open(outfile, 'wb').write(d.content)

    def get_scan_download_list(self, scanner, folders):
        scan_download_list = []
        for folder in folders:
            for item in self.scan_list:
                if item['folder'] == folder['name']:
                    scan_list = self.get_scan_list(scanner, str(folder['id']))
                    if scan_list != None:
                        for scan in scan_list:
                            if scan['status'] == 'completed':
                                scan_download_list.append({'folder': folder['name'], 'id':scan['id'], 'name':scan['name'], 'last_modification_date':scan['last_modification_date']})
                                self.ds.logger.info("Collecting Scans from folder " + folder['name'] + '(' + str(folder['id']) + '): ' + scan['name'] + '(' + str(scan['id']) + ') - ' + (datetime.utcfromtimestamp(int(scan['last_modification_date']))).strftime('%Y-%m-%d %H%M%S'))
                    else:
                        self.ds.logger.info("Collecting Scans from folder " + folder['name'] + '(' + str(folder['id']) + '): ' + 'None')
        return scan_download_list


    def get_scans_list(self, filename):
        try:
            with open(filename) as json_file:
                    scan_list = json.load(json_file)
        except Exception as e:
            self.ds.logger.error("Failed to load db_json_file + " + filename)
            self.ds.logger.error("Exception {0}".format(str(e)))
            self.ds.logger.error("%s" %(traceback.format_exc().replace('\n',';')))
        return scan_list


    def send_scan_to_grid(self, scanner, filename, scan_time):
        asset_list = []
        with open(filename, 'r') as f:
            dicted = csv.DictReader(f)
            vulns = list(dicted)
            for entry in vulns:
                asset = {}
                for key in entry:
                    if entry[key] == "":
                        entry[key] = "None"
                entry['message'] = 'Scan Result - ' + entry['Synopsis']
                entry['scanner'] = scanner
                entry['timestamp'] = scan_time
                self.ds.writeJSONEvent(entry, flatten = False)
                if self.gen_assets_file:
                    asset['Name'] = ''
                    asset['Owner'] = ''
                    asset['Hostnames'] = ''
                    asset['IP Addresses'] = entry['ip address']
                    asset['MAC Addresses'] = ''
                    asset['Importance'] = ''
                    asset['Labels'] = ''
                    asset['Description'] = ''
                    asset_list.append(asset)

    def upload_nessus_to_ticket(self, file_name):
        '''
        size = os.path.getsize(file_name)
        if size > 15728640:
            self.ds.logger.info('File is larger than 15MB, trying to compress: ' + file_name)
            try:
                file_name = self.zipFile(file_name)
                size = os.path.getsize(file_name)
                if size > 15728640:
                    self.ds.logger.error('File is larger than 15MB after compress  Cannot Upload: ' + file_name)
                    return None
            except:
                self.ds.logger.error('Failed to zip the file: ' + file_name)
                self.ds.logger.error("%s" %(traceback.format_exc().replace('\n',';')))
                return None
        '''
        tickets = self.ds.searchTickets(criteria = {"state":["Open"],"task_schedule_id":self.grid_task_schedule_id})
        if tickets == None:
            self.ds.logger.error('Error searching tickets')
        this_ticket = None
        for ticket in tickets:
            this_ticket = ticket
        if 'slug_id' not in this_ticket.keys():
            self.ds.logger.info('Error getting  ticket id from search list')
            return None
        ticket_id = this_ticket['slug_id']
        self.ds.logger.info('Found ticket ' + str(ticket_id) + '. Uploading scan ' + file_name)

        if not self.ds.uploadFileToTicket(ticket_id, file_name):
            self.ds.logger.error('Failed uploading file')
        return file_name

    def zipFile(self, file_name):
        zipped_file = file_name + '.zip'
        try:
            zipf = zipfile.ZipFile(zipped_file, 'w', zipfile.ZIP_DEFLATED)
            zipf.write(file_name)
            zipf.close()
            os.remove(file_name)
        except:
            self.logger.error('Failed to zip the file: ' + file_name)
            self.logger.error("%s" %(traceback.format_exc().replace('\n',';')))
            return None
        return zipped_file



    def nessus_main(self): 

        # Get nessus Config info
        self.upload_scans_to_grid = False

        try:
            self.user = self.ds.config_get('nessus', 'user')
            self.password = self.ds.config_get('nessus', 'password')
            self.scanner_list = self.ds.config_get('nessus', 'scanner').split(',')
            self.state_dir = self.ds.config_get('nessus', 'state_dir')
            self.scan_list_file = self.ds.config_get('nessus', 'scan_list')
            self.sleep_period = self.ds.config_get('nessus', 'sleep_period')
            self.days_ago = self.ds.config_get('nessus', 'days_ago')
            ingest_events = self.ds.config_get('nessus', 'ingest_events')
            if ingest_events.lower() == 'true':
                self.ingest_events = True
            else:
                self.ingest_events = False

            self.last_run = self.ds.get_state(self.state_dir)

            self.time_format = "%Y-%m-%d %H:%M:%S"

            current_time = time.time()

            if self.last_run == None:
                self.ds.logger.info("No previous state.  Collecting logs for last " + str(self.days_ago) + " days")
                #self.last_run = (datetime.utcfromtimestamp((current_time - ( 60 * 60 * 24 * int(self.days_ago))))).strftime(self.time_format)
                self.last_run = current_time - ( 60 * 60 * 24 * int(self.days_ago))
            self.current_run = current_time
        except Exception as e:
                self.ds.logger.error("Failed to get required configurations")
                self.ds.logger.error("Exception {0}".format(str(e)))
                self.ds.logger.error("%s" %(traceback.format_exc().replace('\n',';')))

        try:
            self.grid_secret = self.ds.config_get('grid', 'secret')
            self.grid_key = self.ds.config_get('grid', 'key')
            self.grid_task_schedule_id = self.ds.config_get('grid', 'task_schedule_id')
            if (self.grid_secret != '') and (self.grid_key != '') and (self.grid_task_schedule_id != ''):
                self.upload_scans_to_grid = True
            else:
                self.ds.logger.info("Incomplete config for uploading scan to ticket...skipping")
        except Exception as e:
                self.ds.logger.error("Failed to get required configurations")


        self.scan_list = self.get_scans_list(self.scan_list_file)
        for scanner in self.scanner_list:

            self.token = self.get_token(scanner)
            if self.token == None:
                self.ds.logger.error("Failed to get token for scanner: " + scanner)
                return
            self.headers = {'X-Cookie': self.token, 'Content-type': 'application/json', 'Accept': 'text/plain'}

            folders = self.get_folders(scanner)
            if folders == None:
                self.ds.logger.error("No folders found")
                return
            self.scan_download_list = self.get_scan_download_list(scanner, folders)


            for scan in self.scan_download_list:
                scan_time = (datetime.utcfromtimestamp(int(scan['last_modification_date']))).strftime('%Y-%m-%dT%H:%M:%S') + 'Z'
                filename = scan['folder'] + '-' + scan['name'] + '-' + scan_time
                filename  = filename.replace(' ', '_')
                if self.upload_scans_to_grid:
                    nessus_filename  = filename + ".nessus"
                    self.get_scan(scanner, scan_id = scan['id'], outfile=filename, out_format = 'nessus')
                    uploaded_filename = self.upload_nessus_to_ticket(nessus_filename)
                    if uploaded_filename == None:
                        self.ds.logger.error('Failed to upload the file to the ticket...continuing')
                        if not self.keep_files:
                            os.remove(nessus_filename)
                    else:
                        if not self.keep_files:
                            os.remove(uploaded_filename)
                if self.ingest_events:
                    csv_filename  = filename+".csv"
                    self.get_scan(scanner, scan_id = scan['id'], outfile=filename, out_format = 'csv')
    
                    self.send_scan_to_grid(scanner, filename=csv_filename, scan_time = scan_time)
                    if not self.keep_files:
                        os.remove(csv_filename)

            self.ds.set_state(self.state_dir, self.current_run)
            self.ds.logger.info("Done Sending Notifications")


    def run(self):
        try:
            pid_file = self.ds.config_get('nessus', 'pid_file')
            fp = io.open(pid_file, 'w')
            try:
                fcntl.lockf(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except IOError:
                self.ds.logger.error("An instance of this integration is already running")
                # another instance is running
                sys.exit(0)
            self.nessus_main()
        except Exception as e:
            self.ds.logger.error("Exception {0}".format(str(e)))
            self.ds.logger.error("%s" %(traceback.format_exc().replace('\n',';')))
            return
    
    def usage(self):
        print (os.path.basename(__file__))
        print ('\n  No Options: Run a normal cycle\n')
        print ('  -t    Testing mode.  Do all the work but do not send events to GRID via ')
        print ('        syslog Local7.  Instead write the events to file \'output.TIMESTAMP\'')
        print ('        in the current directory\n')
        print ('  -l    Log to stdout instead of syslog Local6\n')
        print ('  -a    Generate a .csv file that can be used for Asset Import in Grid\n')
        print ('  -k    Keep scan files (.nessus and .csv files)\n')
    
    def __init__(self, argv):

        self.testing = False
        self.send_syslog = True
        self.ds = None
        self.conf_file = None
        self.conn_url = None
        self.gen_assets_file = False
        self.keep_files = False
    
        try:
            opts, args = getopt.getopt(argv,"htlkac:")
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
            elif opt in ("-k"):
                self.keep_files = True
    
        try:
            self.ds = DefenseStorm('nessusScanResults', testing=self.testing, send_syslog = self.send_syslog, config_file = self.conf_file)
        except Exception as e:
            traceback.print_exc()
            try:
                self.ds.logger.error('ERROR: ' + str(e))
            except:
                pass


if __name__ == "__main__":
    i = integration(sys.argv[1:]) 
    i.run()
