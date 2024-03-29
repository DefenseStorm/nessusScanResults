Nessus Integration for DefenseStorm

to pull this repository and submodules:

git clone --recurse-submodules https://github.com/DefenseStorm/nessusScanResults.git

If this is the first integration on this DVM, Do the following:
cp ds-integration/ds_events.conf /etc/syslog-ng/conf.d

Edit /etc/syslog-ng/syslog-ng.conf and add local7 to the excluded list for filter f_syslog3 and filter f_messages. The lines should look like the following:

filter f_syslog3 { not facility(auth, authpriv, mail, local7) and not filter(f_debug); };

filter f_messages { level(info,notice,warn) and not facility(auth,authpriv,cron,daemon,mail,news,local7); };

Restart syslog-ng service syslog-ng restart

Copy the template config file and update the settings
cp nessusScanResults.conf.template nessusScanResults.conf

change the following items in the config file based on your configuration token console site

user = <Nessus Scanner local username>
password = <Nessus Scanner local password>
scanner = <comma separated list of scanners (no spaces)
scan_list = scans.json (customize if needed)

Add these modules if they are not yet there:
apt-get install python3-requests

Add the following entry to the root crontab so the script will run every day at 2am.

0 2 * * * cd /usr/local/nessusScanResults; ./nessusScanResults.py
