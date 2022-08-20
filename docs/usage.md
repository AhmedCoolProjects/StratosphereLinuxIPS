# Usage

Slips can read the packets directly from the **network interface** of the host machine, and packets and flows from different types of files, including

- Pcap files (internally using Zeek) 
- Packets directly from an interface (internally using Zeek)
- Suricata flows (from JSON files created by Suricata, such as eve.json)
- Argus flows (CSV file separated by commas or TABs) 
- Zeek/Bro flows from a Zeek folder with log files
- Nfdump flows from a binary nfdump file
- Text flows from stdin in zeek, argus or suricata form

It's recommended to use PCAPs.

All the input flows are converted to an internal format. So once read, Slips works the same with all of them. 

After Slips was run on the traffic, the Slips output can be analyzed with Kalipso GUI interface. In this section, we will explain how to execute each type of file in Slips, and the output can be analyzed with Kalipso.

Either you are [running Slips in docker](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#installing-and-running-slips-inside-a-docker) or [locally](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#installing-slips-in-your-own-computer), you can run Slips using the same below commands and configurations.
	

## Reading the input

The table below shows the commands Slips uses for different inputs. The first part of the command **./slips.py -c slips.conf** is same, the second part changes depending on the input type. Also, the user can execute **./slips.py --help** to find correct argument to run Slips on each type of the file.

<style>
table {
  font-family: arial, sans-serif;
  border-collapse: collapse;
  width: 100%;
}

td, th {
  border: 1px solid #dddddd;
  text-align: left;
  padding: 8px;
}

tr:nth-child(even) {
  background-color: #dddddd;
}
</style>



<table>
	<tr>
		<th>File/interface</th>
		<th>Argument</th>
		<th>Example command</th>
	</tr>
	<tr>
		<td>Network interface (*)</td>
		<td>-i</td>
		<td>./slips.py -i en0</td>
	</tr>
	<tr>
		<td>pcap</td>
		<td>-f</td>
		<td>./slips.py -f test.pcap</td>
	</tr>
	<tr>
		<td>Argus binetflow</td>
		<td>-f</td>
		<td>./slips.py -f test.binetflow</td>
	</tr>
	<tr>
		<td>Zeek/Bro folder/log</td>
		<td>-f</td>
		<td>./slips.py -f zeek_files</td>
	</tr>
	<tr>
		<td>Nfdump flow</td>
		<td>-f</td>
		<td>./slips.py -f test.nfdump </td>
	</tr>
    <tr>
		<td>stdin</td>
		<td>-f</td>
		<td>./slips.py -f zeek </td>
	</tr>    

</table>

(*) To find the interface in Linux, you can use the command ```ifconfig```.

There is also a configuration file **slips.conf** where the user can set up parameters for Slips execution and models
separately. Configuration of the **slips.conf** is described [here](#modifying-the-configuration-file).

## Daemonized vs interactive mode

Slips has 2 modes, interactive and daemonized.

**Daemonized** : means , output, logs and alerts are written in files.

In daemonized mode : Slips runs completely in the background, The output is written to``` stdout```, ```stderr``` and
```logsfile``` files specified in ```slips.conf``` 

by default, these are the paths used

stdout = /var/log/slips/slips.log
stderr = /var/log/slips/error.log
logsfile = /var/log/slips/slips.log

NOTE: Since ```/val/log/``` is owned by root by default, If you want to store the logs in  ```/var/log/slips```, 
creat /var/log/slips as root and slips will use it by default.

If slips can't write there, slips will store the logs in the ```Slips/output/``` dir by default.

NOTE: if -o <output_dir> is given when slips is in daemonized mode, the output log files will be stored in <output_dir>
 instead of the otput_dir specified in slips.conf 



This is the not the default mode, to use it, run slips with -D


```./slips.py -i wlp3s0 -D```

To stop the daemon run slips with ```-S```, for example ```./slips.py -S```


Only one instance of the daemon can be running at a time.

**Interactive** : For viewing output, logs and alerts in a terminal, usually used for developers and debugging.
 
This is the default mode, It doesn't require any flags.

Output files are stored in ```output/``` dir.

By default you don't need root to run slips, but if you changed the default output directory to a dir that is 
owned by root, you will need to run Slips using sudo or give the current user enough permission so that
slips can write to those files. 



For detailed information on how slips uses redis check the 
[Running several slips instances section](https://stratospherelinuxips.readthedocs.io/en/develop/usage.html#running-several-slips-instances)


## Running Several slips instances

By default, Slips will assume you are running only 1 instance and will use the redis port 6379 on each run.

You can run several instances of slips at the same time using the -m flag, and the output of each instance will be stored in
```output/filename_timestamp/```  directory. 

Each instance of Slips will connect to redis server on a randomly generated port in the range (32768 to 32850).

In macos, you will get a popup asking for permission to open and use that random port, press yes to allow it.

However, all instance share 1 cached redis database on redis://localhost:6379 DB 1, to store the IoCs taken from TI files.

Both redis servers, the main sever (DB 0) and the cache server (DB 1) are opened automatically by Slips.

When running ./kalipso.sh, you will be prompted with the following

    To close all unused redis servers, run slips with --killall
    You have 3 open redis servers, Choose which one to use [1,2,3 etc..] 
    [1] wlp3s0 - port 55879
    [2] dataset/hide-and-seek-short.pcap - port 59324

You can type 1 or 2 to view the corresponding file or interface in kalipso.

Once you're done, you can run slips with ```--killall``` to close all the redis servers using the following command

```./slips.py --killall```

NOTICE: if you run more than one instance of Slips on the same file or the same interface, 
Slips will generate a new directory with the name of the file and the new timestamp inside the ```output/``` dir

## Closing redis servers

Slips uses a random unused port in the range in the range (32768 to 32850).

When running slips, it will warn you if you have more than 1 redis serve open using the following msg
    
    [Main] Warning: You have 2 redis servers running. Run Slips with --killall to stop them.

you can use the -k flag to kill 1 open redis server, or all of them using the following command
    
    ./slips.py -k

You will be prompted with the following options

    Choose which one to kill [0,1,2 etc..]
    
    [0] Close all servers
    [1] dataset/sample_zeek_files - port 32768
    [2] dataset/sample_zeek_files - port 32769
    [3] dataset/sample_zeek_files - port 32770

you can select the number you want to kill or 0 to close all the servers.

Note that if all ports from (32768 to 32850) are unavailable, slips won't be able to start, and you will 
be asked to close all all of them using the following warning

    All ports from 32768 to 32769 are used. Unable to start slips.
    
    Press Enter to close all ports.

You can press enter to close all ports, then start slips again.

## Reading the output
The output process collects output from the modules and handles the display of information on screen. Currently, Slips'
analysis and detected malicious behaviour can be analyzed as following:

- **Kalipso** - Node.JS based graphical user interface in the terminal. Kalipso displays Slips detection and analysis in colorful table and graphs, highlighting important detections. See section Kalipso for more explanation.
- **alerts.json and alerts.txt in the output folder** - collects all evidences and detections generated by Slips in a .txt and .json formats.
- **log files in a folder _current-date-time_** - separates the traffic into files according to a profile and timewindow and summarize the traffic according to each profile and timewindow.

There are two options how to run Kalipso Locally:
1. You can run Kalipso as a shell script in another terminal using the command:

	```./kalipso.sh```


In docker, you can open a new terminal inside the slips container and execute ```./kalipso.sh```

To open a new terminal inside Slips container first [run](https://stratospherelinuxips.readthedocs.io/en/develop/installation.html#running-slips-inside-a-docker-from-the-dockerhub) Slips in one terminal

Now in a new local terminal get the Slips container ID:

```docker ps```

Create another terminal of the Slips container using 

```docker exec -it <container_id> bash```

Now you can run 

```./kalipso.sh```

## Saving the database

Slips uses redis to store analysis information. you can save your analysis for later use by running slips with ```-s```, 

For example:

```./slips.py -f dataset/hide-and-seek-short.pcap -s```

Your .rdb saved database will be stored in ```redis_backups/```.

Note: If you try to save the same file twice using ```-s``` the old backup will be overwritten.

You can load it again using ```-d```, For example:

```./slips.py -d redis_backups/hide-and-seek-short.rdb ```

And then use ```./kalipso``` and select the entry on port 6379 to view the loaded database.

This feature isn't supported in docker due to problems with redis in docker.

_DISCLAIMER_: When saving the database you will see the following
warning 

    stop-writes-on-bgsave-error is set to no, information may be lost in the redis backup file

This configuration is set by slips so that redis will continue working even if redis
can't write to dump.rdb. 

Your information will be lost only if you're out of space and redis can't write to dump.rdb or if you 
don't have permissions to write to /var/lib/redis/dump.rdb, otherwise you're fine and 
the saved database will contain all analyzed flows.


## Whitelisting
Slips allows you to whitelist some pieces of data in order to avoid its processing. 
In particular you can whitelist an IP address, a domain, a MAC address or a complete organization. 
You can choose to whitelist what is going __to__ them and what is coming __from__ them. 
You can also choose to whitelist the flows, so they are not processed, or the alerts, so
you see the flows but don't receive alerts on them. The idea of whitelisting is to avoid
processing any communication to or from these pieces of data, not to avoid any packet that
contains that piece of data. For example, if you whitelist the domain slack.com, then a DNS 
request to the DNS server 1.2.3.4 asking for slack.com will still be shown.

### Flows Whitelist
If you whitelist an IP address, Slips will check all flows and see if you are whitelisting to them or from them.

If you whitelist a domain, Slips will check:
- Domains in HTTP Host header
- Domains in the SNI field of TLS flows
- All the Domains in the DNS resolution of IPs (there can be many) (be careful that the resolution takes time, which means that some flows may not be whitelisted because Slips doesn't know they belong to a domain).
- Domains in the CN of the certificates in TLS

If you whitelist an organization, then:
- Every IP is checked against all the known IP ranges of that organization
- Every domain (SNI/HTTP Host/IP Resolution/TLS CN certs) is checked against all the known domains of that organization
- ASNs of every IP are verified against the known ASN of that organization

If you whitelist a MAC address, then:
- The source and destination MAC addresses of all flows are checked against the whitelisted mac address.


### Alerts Whitelist

If you whitelist some piece of data not to generate alerts, the process is the following:

- If you whitelisted an IP
    - We check if the source or destination IP of the flow that generated that alert is whitelisted.
    - We check if the content of the alert is related to the IP that is whitelisted.
  
- If you whitelisted a domain
    - We check if any domain in alerts related to DNS/HTTP Host/SNI is whitelisted. 
    - We check also if any domain in the traffic is a subdomain of your whitelisted domain. So if you whitelist 'test.com', we also match 'one.test.com'
  
- If you whitelisted an organization
    - We check that the ASN of the IP in the alert belongs to that organization.
    - We check that the range of the IP in the alert belongs to that organization.
  
- If you whitelist a MAC address, then:
  - The source and destination MAC addresses of all flows are checked against the whitelisted mac address.

### Whitelisting Example
You can modify the file ```whitelist.csv``` file with this content:


    "IoCType","IoCValue","Direction","IgnoreType"
    ip,1.2.3.4,both,alerts
    domain,google.com,src,flows
    domain,apple.com,both,both
    ip,94.23.253.72,both,alerts
    ip,91.121.83.118,both,alerts
    mac,b1:b1:b1:c1:c2:c3,both,alerts
    organization,microsoft,both,both
    organization,facebook,both,both
    organization,google,both,both
    organization,apple,both,both
    organization,twitter,both,both

The values for each column are the following:

    Column IoCType
        - Supported IoCTypes: ip, domain, organization, mac
    Column IoCValue
        - Supported organizations: google, microsoft, apple, facebook, twitter.
    Column Direction
        - Direction: src, dst or both
            - Src: Check if the IoCValue is the source
            - Dst: Check if the IoCValue is the destination
            - Both: Check if the IoCValue is the source or destination
    Column IgnoreType
        - IgnoreType: alerts or flows or both
            - Ignore alerts: slips reads all the flows, but it just ignores alerting if there is a match.
            - Ignore flows: the flow will be completely discarded.



## Popup notifications

Slips Support displaying popup notifications whenever there's an alert. 

This feature is disabled by default. You can enable it by changing ```popup_alerts``` to ```yes``` in ```slips.conf``` 

This feature is supported in Linux and it requires root privileges.

This feature is supported in MaOS without root privileges.

This feature is not supported in Docker

## Slips permissions

Slips doesn't need root permissions unless you

1. use the blocking module ( with -p )
2. use slips notifications
3. are saving the database ( with -d )

If you can't listen to an interface without sudo, you can run the following command to let any user use zeek to listen to an interface not just root.

```
setcap cap_net_raw,cap_net_admin=eip /<path-to-zeek-bin/zeek
```

Even when Slips is run using sudo, it drops root privileges  in modules that don't need them.


## Modifying the configuration file

Slips has a ```slips.conf``` the contains user configurations for different modules and general execution. Below are some of Slips features that can be modifie with respect to the user preferences.

### Generic configuration

**Time window width.**

Each IP address that appears in the network traffic of the input is represented as a profile in Slips. Each profile is divided into time windows. Each time window is 1 hour long by default, and it gathers the network traffic and its behaviour for the period of 1 hour. The duration of the timewindow can be changed in the the slips.conf using

```time_window_width```

**Home Network**

Slips needs to know your home network to be able to use specific zeek scripts. 

If ```home_network``` is not defined, Slips uses all ranges ```'192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8``` as your local network.


When the ```home_network``` parameter is set, slips creates profiles only for ips inside the home network, check the analysis direction below.

**Analysis Direction**


```analysis_direction``` can either be ```out``` or ```all```

<div class="zoom">
<img style="max-width:500px;max-height:500px;" src="https://raw.githubusercontent.com/stratosphereips/StratosphereLinuxIPS/develop/docs/images/directions.png" title="Figure 1. Out and all directions">
</div>


### Disabling a module

You can disable modules easily by appending the module name to the ```disable``` list.

### ML Detection

The ```mode=train``` should be used to tell the MLdetection1 module that the flows received are all for training.

The ```mode=test``` should be used after training the models, to test unknown data. 

You should have trained at least once with 'Normal' data and once with 'Malicious' data in order for the test to work.

### Blocking

This module is enabled only using the ```-p``` parameter and needs an interface to run. 

Usage example:

```sudo ./slips.py -i wlp3s0 -p```

Slips needs to be run as root so it can execute iptables commands. 

In Docker, since there's no root, the environment variable ```IS_IN_A_DOCKER_CONTAINER``` should be set to ```True``` to use 'sudo' properly.

If you use the latest Dockerfile, it will be set by default. If not, you can set it manually by running this command in the docker container

```export IS_IN_A_DOCKER_CONTAINER=True```



### Anomaly Detection

The ```anomaly_detection_mode= training``` should be used to tell the module that the flows received are all for training.

The ```anomaly_detection_mode= testing``` should be used after training the models, to test unknown data. 

```Testing``` is the default mode.

### VirusTotal

In order for virustotal module to work, you need to add your VirusTotal API key to the file
```modules/virustotal/api_key_secret```.

You can specify the path to the file with VirusTotal API key in the ```api_key_file``` variable.

The file should contain the key at the start of the first line, and nothing more.

If no key is found, virustotal module will not start.


### Exporting Alerts

Slips can export alerts to different systems.

Refer to the [exporting section of the docs](https://stratospherelinuxips.readthedocs.io/en/develop/exporting.html) for detailed instructions on how to export.


### Logging

To enable the creation of log files, there are two options:
1. Running Slips with ```-l``` flag. 
2. Setting ```create_log_files``` to ```yes``` in ```slips.conf```.
3. Running Slips with ```verbose``` and ```debug``` flags
4. Using errors.log and running.log

#### Running Slips with -l flag.

When logging is enabled, Slips will create a directory with the current date and 
create 3 summary files for each IP/profile it encounters.

Summaries created contain profile data, complete timeline outgoing actions and timeline of all traffic that involves this IP.

You can also change how often Slips creates log files using the ```log_report_time``` variable  in ```slips.conf```.

You can enable or disable deleting zeek log files after stopping slips by setting ```delete_zeek_files``` to  yes or no.

DISCLAIMER: zeek generates log files that grow every second until they reach GBs, to save disk space, Slips deletes all zeek log files after 1 day by default. this is called zeek rotation and is enabled by default.

You can disable rotation by setting ```rotation``` to ```no``` in ```slips.conf```

But you can also enable storing a copy of zeek log files in the output directory by setting ```store_a_copy_of_zeek_files``` to yes. this option stores a copy of the zeek files present in ```zeek_files/``` the moment slips stops. so this doesn't include deleted zeek logs.

Once slips is done, you will find a copy of your zeek files in ```<output_dir>/zeek_files/```

DISCLAIMER: Once slips knows you do not want a copy of zeek log files after slips is done by enabling
 ```delete_zeek_files``` and disabling ```store_a_copy_of_zeek_files``` parameters,
it deletes large log files periodically (like arp.log).

####  Running Slips with verbose and debug flags

We use two variables for logging, ```verbose``` and ```debug```, they both range from 0 to 3.

Default value for both of them is 0

To change them, We use ```-v``` for verbosity and ```-e``` for debugging

For example:

```./slips.py -c slips.conf -v 2 -e 1 -f zeek_dir ```

Verbosity is about less or more information on the normal work of slips. 

For example: "Done writing logs to file x."

Debug is only about errors.

For example: "Error reading threat intelligence file, line 4, column 2"

To more verbosity level, the more detailed info is printed.

The more debug level, the more errors are logged.

Below is a table showing each level of both.

<table>
<tbody>
<tr style="height: 22px;">
<td style="height: 22px;">&nbsp;</td>
<td style="height: 22px;">&nbsp;Verbosity</td>
<td style="height: 22px;">&nbsp;Debugging</td>
</tr>
<tr style="height: 22px;">
<td style="height: 22px;">&nbsp;0</td>
<td style="height: 22px;">&nbsp;Don't&nbsp;print</td>
<td style="height: 22px;">&nbsp;Don't print</td>
</tr>
<tr style="height: 22px;">
<td style="height: 22px;">1&nbsp;</td>
<td style="height: 22px;">&nbsp;Show basic operation, proof of work&nbsp;</td>
<td style="height: 22px;">&nbsp;Print exceptions</td>
</tr>
<tr style="height: 22px;">
<td style="height: 22px;">2&nbsp;</td>
<td style="height: 22px;">&nbsp;Log I/O operations and filenames</td>
<td style="height: 22px;">&nbsp;Unsupported and unhandled types (cases that may cause errors)</td>
</tr>
<tr style="height: 22px;">
<td style="height: 22px;">3&nbsp;</td>
<td style="height: 22px;">&nbsp;Log database/profile/timewindow changes</td>
<td style="height: 22px;">&nbsp;Red warnings that need examination - developer warnings</td>
</tr>
</tbody>
</table>

#### Using errors.log and running.log

Slips also logs all errors to output/errors.log (interactive mode), and /var/log/slips/error.log (daemonized mode)
whether you're using -e or not.
See [Daemonized vs interactive](https://stratospherelinuxips.readthedocs.io/en/develop/usage.html#daemonized-vs-interactive-mode)
for more information about the 2 modes

General slips logs are created in /var/log/slips/running.log in case of daemonized mode and ...#TODO in case of
interactive mode

## Reading Input from stdin

Slips supports reading input flows in text format from stdin in interactive mode.

Supported flow from stdin are zeek conn.log files (json form), suricata and argus.

For example you can run slips using:

```./slips.py -f zeek```

or

```./slips.py -f suricata```

and you once you see the following line:

```[InputProcess] Receiving flows from stdin.```

you can start giving slips flows in you desired format.

All zeek lines taken from stdin should be in json form and are treated as conn.log lines.

This feature is specifically designed to allow slips to interact with network simulators and scripts.

## Plug in a zeek script

Slips supports automatically running a custom zeek script by adding it to ```zeek-scripts``` dir and adding the file
name in ```zeek-scripts/__load__.zeek```.

For example, if you want to add a zeek script called ```arp.zeek``` you should add it to ```__load__.zeek``` like this:

	@load ./arp.zeek

Zeek output is suppressed by default, so if your script has errors, Slips will fail silently.

## Getting slips version

You can check out your running slips version using ```-V``` or ```--version``` flags.


## Running Slips from python

You can run Slips from python using the following script

```py
import subprocess
command = './slips.py -f dataset/test3.binetflow -o /data/test'
args = command.split()
process = subprocess.run(args, stdout=subprocess.PIPE)
```