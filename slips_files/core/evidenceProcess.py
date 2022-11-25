# Stratosphere Linux IPS. A machine-learning Intrusion Detection System
# Copyright (C) 2021 Sebastian Garcia

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
# Contact: eldraco@gmail.com, sebastian.garcia@agents.fel.cvut.cz, stratosphere@aic.fel.cvut.cz
import multiprocessing
from slips_files.core.database.database import __database__
from slips_files.common.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from .notify import Notify
import json
from datetime import datetime
from os import path
from colorama import Fore, Style
import sys
import os
from .whitelist import Whitelist
import time
import platform


# Evidence Process
class EvidenceProcess(multiprocessing.Process):
    """
    A class to process the evidence from the alerts and update the threat level
    It only work on evidence for IPs that were profiled
    This should be converted into a module
    """

    def __init__(
        self,
        inputqueue,
        outputqueue,
        output_folder,
        logs_folder,
        redis_port,
    ):
        self.name = 'Evidence'
        multiprocessing.Process.__init__(self)
        self.inputqueue = inputqueue
        self.outputqueue = outputqueue
        self.whitelist = Whitelist(outputqueue, redis_port)
        __database__.start(redis_port)
        self.separator = __database__.separator
        # Read the configuration
        self.read_configuration()
        self.detection_threshold_in_this_width = self.detection_threshold * self.width / 60
        # If logs enabled, write alerts to the log folder as well
        self.clear_logs_dir(logs_folder)
        if self.popup_alerts:
            self.notify = Notify()
            if self.notify.bin_found:
                # The way we send notifications differ depending on the user and the OS
                self.notify.setup_notifications()
            else:
                self.popup_alerts = False

        # Subscribe to channel 'evidence_added'
        self.c1 = __database__.subscribe('evidence_added')
        self.c2 = __database__.subscribe('new_blame')
        # clear alerts.log
        self.logfile = self.clean_file(output_folder, 'alerts.log')

        # clear alerts.json
        self.jsonfile = self.clean_file(output_folder, 'alerts.json')
        self.print(f'Storing Slips logs in {output_folder}')
        # this list will have our local and public ips when using -i
        self.our_ips = utils.get_own_IPs()

        # all evidence slips detects has threat levels of strings
        # each string should have a corresponding int value to be able to calculate
        # the accumulated threat level and alert
        # flag to only add commit and hash to the firs alert in alerts.json
        self.is_first_alert = True

    def clear_logs_dir(self, logs_folder):
        self.logs_logfile = False
        self.logs_jsonfile = False
        if logs_folder:
            # these json files are inside the logs dir, not the output/ dir
            self.logs_jsonfile = self.clean_file(
                logs_folder, 'alerts.json'
                )
            self.logs_logfile = self.clean_file(
                logs_folder, 'alerts.log'
                )

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the processes into account
        :param verbose:
            0 - don't print
            1 - basic operation/proof of work
            2 - log I/O operations and filenames
            3 - log database/profile/timewindow changes
        :param debug:
            0 - don't print
            1 - print exceptions
            2 - unsupported and unhandled types (cases that may cause errors)
            3 - red warnings that needs examination - developer warnings
        :param text: text to print. Can include format like 'Test {}'.format('here')
        """

        levels = f'{verbose}{debug}'
        self.outputqueue.put(f'{levels}|{self.name}|{text}')

    def read_configuration(self):
        conf = ConfigParser()
        self.width = conf.get_tw_width_as_float()
        self.detection_threshold = conf.evidence_detection_threshold()
        self.print(
            f'Detection Threshold: {self.detection_threshold} '
            f'attacks per minute ({self.detection_threshold * int(self.width) / 60} '
            f'in the current time window width)',2,0,
        )

        self.popup_alerts = conf.popup_alerts()
        # In docker, disable alerts no matter what slips.conf says
        if os.environ.get('IS_IN_A_DOCKER_CONTAINER', False):
            self.popup_alerts = False

    def format_blocked_srcip_evidence(self, profileid, twid, flow_datetime):
        """
        Function to prepare evidence about the blocked profileid and twid
        This evidence will be written in alerts.log, it won't be displayed in the terminal
        """
        try:
            now = datetime.now()
            now = utils.convert_format(now, utils.alerts_format)
            ip = profileid.split('_')[-1].strip()
            return f'{flow_datetime}: Src IP {ip:26}. Blocked given enough evidence ' \
                   f'on timewindow {twid.split("timewindow")[1]}. (real time {now})'

        except Exception as inst:
            self.print('Error in print_alert()')
            self.print(type(inst))
            self.print(inst)

    def format_evidence_string(
        self,
        profileid,
        twid,
        ip,
        detection_module,
        detection_type,
        detection_info,
        description,
    ):
        """
        Function to format each evidence and enrich it with more data, to be displayed according to each detection module.
        :return : string with a correct evidence displacement
        """
        evidence_string = ''
        dns_resolution_detection_info = __database__.get_dns_resolution(detection_info)
        dns_resolution_detection_info = dns_resolution_detection_info.get(
            'domains', []
        )
        dns_resolution_detection_info = dns_resolution_detection_info[
                                        :3] if dns_resolution_detection_info else ''

        dns_resolution_ip = __database__.get_dns_resolution(ip)
        dns_resolution_ip = dns_resolution_ip.get('domains', [])
        if len(dns_resolution_ip) >= 1:
            dns_resolution_ip = dns_resolution_ip[0]
        elif len(dns_resolution_ip) == 0:
            dns_resolution_ip = ''
        dns_resolution_ip_final = f' DNS: {dns_resolution_ip[:3]}. ' if dns_resolution_detection_info and len(
            dns_resolution_ip[:3]
            ) > 0 else '. '

        srcip = profileid.split('_')[1]

        if detection_module == 'ThreatIntelligenceBlacklistIP':
            evidence_string = f'Detected {description}'
            # if detection_type == 'srcip':
            #     ip = srcip

        elif detection_module == 'ThreatIntelligenceBlacklistDomain':
            # ip = srcip
            evidence_string = f'Detected {description}'

        elif detection_module == 'SSHSuccessful':
            evidence_string = f'Did a successful SSH. {description}'
        else:
            evidence_string = f'Detected {description}'

        # Add the srcip to the evidence
        # evidence_string = f'IP: {ip} (DNS:{dns_resolution_ip}). ' + evidence_string
        # evidence_string = f'Src IP {ip:15}. ' + evidence_string


        return f'{evidence_string}'
    
    
    def line_wrap(self, txt):
        """
        is called for evidence that are goinng to be printed in the terminal
        line wraps the given text so it looks nice
        """
        # max chars per line
        wrap_at = 155

        wrapped_txt = ''
        for indx in range(0, len(txt), wrap_at):
            wrapped_txt += txt[indx:indx+wrap_at]
            wrapped_txt += f'\n{" "*10}'

        # remove the \n at the end
        wrapped_txt = wrapped_txt[:-11]
        if wrapped_txt.endswith('\n'):
            wrapped_txt = wrapped_txt[:-1]

        return wrapped_txt
        
    
    def clean_file(self, output_folder, file_to_clean):
        """
        Clear the file if exists and return an open handle to it
        """
        logfile_path = os.path.join(output_folder, file_to_clean)
        if path.exists(logfile_path):
            open(logfile_path, 'w').close()
        return open(logfile_path, 'a')

    def addDataToJSONFile(self, IDEA_dict: dict):
        """
        Add a new evidence line to our alerts.json file in json IDEA format.
        :param IDEA_dict: dict containing 1 alert
        """
        try:
            json_alert = '{ '
            for key_, val in IDEA_dict.items():
                if type(val) == str:
                    # strings in json should be in double quotes instead of single quotes
                    json_alert += f'"{key_}": "{val}", '
                else:
                    # int and float values should be printed as they are
                    json_alert += f'"{key_}": {val}, '
            # remove the last comma and close the dict
            json_alert = json_alert[:-2] + ' }\n'
            # make sure all alerts are in json format (using double quotes)
            json_alert = json_alert.replace("'", '"')
            self.jsonfile.write(json_alert)
            self.jsonfile.flush()
        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Error in addDataToJSONFile()')
            self.print(type(inst))
            self.print(inst)

    def addDataToLogFile(self, data):
        """
        Add a new evidence line to the alerts.log and other log files if logging is enabled.
        """
        try:
            # write to alerts.log
            self.logfile.write(data)
            self.logfile.write('\n')
            self.logfile.flush()

            # If logs are enabled, write alerts in the folder as well
            if self.logs_logfile:
                self.logs_logfile.write(data)
                self.logs_logfile.write('\n')
                self.logs_logfile.flush()

        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Error in addDataToLogFile()')
            self.print(type(inst))
            self.print(inst)

    def get_domains_of_flow(self, flow: dict):
        """Returns the domains of each ip (src and dst) that appeared in this flow"""
        # These separate lists, hold the domains that we should only check if they are SRC or DST. Not both
        try:
            flow = json.loads(list(flow.values())[0])
        except TypeError:
            # sometimes this function is called before the flow is add to our database
            return [], []
        domains_to_check_src = []
        domains_to_check_dst = []
        try:
            # self.print(f"IPData of src IP {self.column_values['saddr']}:
            # {__database__.getIPData(self.column_values['saddr'])}")
            domains_to_check_src.append(
                __database__.getIPData(flow['saddr'])
                .get('SNI', [{}])[0]
                .get('server_name')
            )
        except (KeyError, TypeError):
            pass
        try:
            # self.print(f"DNS of src IP {self.column_values['saddr']}:
            # {__database__.get_dns_resolution(self.column_values['saddr'])}")
            src_dns_domains = __database__.get_dns_resolution(flow['saddr'])
            src_dns_domains = src_dns_domains.get('domains', [])

            domains_to_check_src.extend(iter(src_dns_domains))
        except (KeyError, TypeError):
            pass
        try:
            # self.print(f"IPData of dst IP {self.column_values['daddr']}:
            # {__database__.getIPData(self.column_values['daddr'])}")
            domains_to_check_dst.append(
                __database__.getIPData(flow['daddr'])
                .get('SNI', [{}])[0]
                .get('server_name')
            )
        except (KeyError, TypeError):
            pass

        return domains_to_check_dst, domains_to_check_src

    def show_popup(self, alert_to_log: str):
        """
        Function to display a popup with the alert depending on the OS
        """
        if platform.system() == 'Linux':
            #  is notify_cmd is set in setup_notifications function depending on the user
            os.system(f'{self.notify_cmd} "Slips" "{alert_to_log}"')
        elif platform.system() == 'Darwin':
            os.system(
                f'osascript -e \'display notification "{alert_to_log}" with title "Slips"\' '
            )

    def add_to_log_folder(self, data):
        # If logs folder is enabled (using -l), write alerts in the folder as well
        if not self.logs_jsonfile:
            return False
        data_json = json.dumps(data)
        self.logs_jsonfile.write(data_json)
        self.logs_jsonfile.write('\n')
        self.logs_jsonfile.flush()

    def format_evidence_causing_this_alert(
        self, all_evidence, profileid, twid, flow_datetime
    ) -> str:
        """
        Function to format the string with all evidence causing an alert
        flow_datetime: time of the last evidence received
        """
        # alerts in slips consists of several evidence, each evidence has a threat_level
        # once we reach a certain threshold of accumulated threat_levels, we produce an alert
        # Now instead of printing the last evidence only, we print all of them
        try:
            twid_num = twid.split('timewindow')[1]
            srcip = profileid.split(self.separator)[1]
            # Get the start time of this TW
            twid_start_time = None
            while twid_start_time == None:
                # give the database time to retreive the time
                twid_start_time = __database__.getTimeTW(profileid, twid)

            tw_start_time_str = utils.convert_format(twid_start_time,  '%Y/%m/%d %H:%M:%S')
            # datetime obj
            tw_start_time_datetime = utils.convert_to_datetime(tw_start_time_str)

            # Convert the tw width to deltatime
            # tw_width_in_seconds_delta = timedelta(seconds=int(self.width))
            delta_width = utils.to_delta(self.width)

            # Get the stop time of the TW
            tw_stop_time_datetime = (tw_start_time_datetime + delta_width)

            tw_stop_time_str = utils.convert_format(
                tw_stop_time_datetime,
                 '%Y/%m/%d %H:%M:%S'
            )

            hostname = __database__.get_hostname_from_profile(profileid)
            # if there's no hostname, set it as ' '
            hostname = hostname or ''
            if hostname:
                hostname = f'({hostname})'

            alert_to_print = (
                f'{Fore.RED}IP {srcip} {hostname} detected as malicious in timewindow {twid_num} '
                f'(start {tw_start_time_str}, stop {tw_stop_time_str}) \n'
                f'given the following evidence:{Style.RESET_ALL}\n'
            )
        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(
                f'Problem on format_evidence_causing_this_alert() line {exception_line}',0,1,
            )
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True

        for evidence in all_evidence.values():
            # Deserialize evidence
            evidence = json.loads(evidence)
            type_detection = evidence.get('type_detection')
            detection_info = evidence.get('detection_info')
            type_evidence = evidence.get('type_evidence')
            description = evidence.get('description')
            evidence_ID = evidence.get('ID')

            # format the string of this evidence only: for example Detected C&C
            # channels detection, destination IP:xyz
            evidence_string = self.format_evidence_string(
                profileid,
                twid,
                srcip,
                type_evidence,
                type_detection,
                detection_info,
                description,
            )
            evidence_string = self.line_wrap(evidence_string)

            alert_to_print += (
                f'\t{Fore.CYAN}- {evidence_string}{Style.RESET_ALL}\n'
            )

        # Add the timestamp to the alert. The datetime printed will be of the last evidence only
        readable_datetime = utils.convert_format(flow_datetime, utils.alerts_format)
        alert_to_print = f'{Fore.RED}{readable_datetime}{Style.RESET_ALL} {alert_to_print}'
        return alert_to_print

    def decide_blocking(self, profileid) -> bool:
        """
        Decide whether to block or not and send to the blocking module
        :param ip: IP to block
        """
        # # ip_direction is the direction of the last evidence, it's irrelevant! #TODO
        # if ip_direction != 'dstip':
        #     return False
        running_on_interface = '-i' in sys.argv or __database__.is_growing_zeek_dir()
        if not (running_on_interface and '-p' in sys.argv):
            # blocking is only supported when running on an interface
            return False

        # now since this source ip(profileid) caused an alert,
        # it means it caused so many evidence(attacked others a lot)
        # that we decided to alert and block it
        ip_to_block = profileid.split('_')[-1]

        # Make sure we don't block our own IP
        if ip_to_block in self.our_ips:
            return False

        #  TODO: edit the options in blocking_data, by default it'll block
        #  all traffic to or from this ip
        blocking_data = {
            'ip': ip_to_block,
            'block': True,
        }
        blocking_data = json.dumps(blocking_data)
        __database__.publish('new_blocking', blocking_data)
        return True

    def mark_as_blocked(
            self, profileid, twid, flow_datetime, accumulated_threat_level
    ):
        __database__.markProfileTWAsBlocked(profileid, twid)
        # Add to log files that this srcip is being blocked
        blocked_srcip_to_log = (
            self.format_blocked_srcip_evidence(
                profileid, twid, flow_datetime
            )
        )
        self.addDataToLogFile(blocked_srcip_to_log)

        blocked_srcip_dict = {
            'type': 'alert',
            'profileid': profileid,
            'twid': twid,
            'threat_level': accumulated_threat_level,
        }
        self.add_to_log_folder(blocked_srcip_dict)

    def shutdown_gracefully(self):
        self.logfile.close()
        self.jsonfile.close()
        __database__.publish('finished_modules', 'Evidence')

    def delete_alerted_evidence(self, proflied, twid, tw_evidence):
        """
        if there was an alert in this tw before, remove the evidence that were part of the past alert
        from the current evidence
        """
        # format of tw_evidence is {<ev_id>: {evidence_details}}
        past_alerts = __database__.get_profileid_twid_alerts(proflied, twid)
        if not past_alerts:
            return tw_evidence

        for alert_id, evidence_IDs in past_alerts.items():
            evidence_IDs = json.loads(evidence_IDs)
            for ID in evidence_IDs:
                tw_evidence.pop(ID, None)
        return tw_evidence

    def delete_whitelisted_evidence(self, evidence):
        """
        delete the hash of all whitelisted evidence from the given dict of evidence ids
        """
        res = {}
        for evidence_ID, evidence_info in evidence.items():
            # sometimes the db has evidence that didnt come yet to evidenceprocess
            # and they are alerted without checking the whitelist!
            # to fix this, we have processed evidence which are
            # evidence that came to new_evidence channel and were processed by it
            # so they are ready to be a part of an alerted
            if (
                    not __database__.is_whitelisted_evidence(evidence_ID)
                    and __database__.is_evidence_processed(evidence_ID)
            ):
                res[evidence_ID] = evidence_info
        return res

    def delete_evidence_done_by_others(self, tw_evidence):
        """
        given all the tw evidence, we should only consider evidence that makes this given
        profile malicious, aka evidence of this profile attacking others.
        """
        res = {}
        for evidence_ID, evidence_info in tw_evidence.items():
            evidence_info = json.loads(evidence_info)
            type_detection = evidence_info.get('type_detection', '')
            # the following type detections are the ones
            # expected to be seen when we are attacking others
            # marking this profileid (srcip) as malicious
            if type_detection in ('srcip', 'sport', 'srcport'):
                res[evidence_ID] = json.dumps(evidence_info)

        return res


    def get_evidence_for_tw(self, profileid, twid):
        # Get all the evidence for this profile in this TW
        tw_evidence = __database__.getEvidenceForTW(
            profileid, twid
        )
        if not tw_evidence:
            return False

        tw_evidence: dict = json.loads(tw_evidence)
        tw_evidence = self.delete_alerted_evidence(profileid, twid, tw_evidence)
        tw_evidence = self.delete_evidence_done_by_others( tw_evidence)
        tw_evidence = self.delete_whitelisted_evidence(tw_evidence)
        return tw_evidence


    def get_accumulated_threat_level(self, tw_evidence):
        accumulated_threat_level = 0.0
        # to store all the ids causing this alerts in the database
        self.IDs_causing_an_alert = []
        for evidence in tw_evidence.values():
            evidence = json.loads(evidence)
            # type_detection = evidence.get('type_detection')
            # detection_info = evidence.get('detection_info')
            type_evidence = evidence.get('type_evidence')
            confidence = float(evidence.get('confidence'))
            threat_level = evidence.get('threat_level')
            description = evidence.get('description')
            ID = evidence.get('ID')
            self.IDs_causing_an_alert.append(ID)
            # each threat level is a string, get the numerical value of it
            try:
                threat_level = utils.threat_levels[
                    threat_level.lower()
                ]
            except KeyError:
                self.print(
                    f'Error: Evidence of type {type_evidence} has '
                    f'an invalid threat level {threat_level}', 0, 1
                )
                self.print(f'Description: {description}', 0, 1)
                threat_level = 0

            # Compute the moving average of evidence
            new_threat_level = threat_level * confidence
            self.print(
                f'\t\tWeighted Threat Level: {new_threat_level}', 3, 0
            )
            accumulated_threat_level += new_threat_level
            self.print(
                f'\t\tAccumulated Threat Level: {accumulated_threat_level}', 3, 0,
            )
        return accumulated_threat_level

    def get_last_evidence_ID(self, tw_evidence):
        last_evidence_ID = list(tw_evidence.keys())[-1]
        return last_evidence_ID

    def send_to_exporting_module(self, tw_evidence):
        for evidence in tw_evidence.values():
            __database__.publish('export_evidence', evidence)

    def run(self):
        # add metadata to alerts.log
        branch_info = utils.get_branch_info()
        if branch_info != False:
            # it's false when we're in docker because there's no .git/ there
            commit, branch = branch_info[0], branch_info[1]
            now = datetime.now()
            self.logfile.write(f'Using {branch} - {commit} - {now}\n\n')

        while True:
            try:
                # Adapt this process to process evidence from only IPs and not profileid or twid

                # Wait for a message from the channel that a TW was modified
                message = __database__.get_message(self.c1)

                if utils.is_msg_intended_for(message, 'evidence_added'):
                    # Data sent in the channel as a json dict, it needs to be deserialized first
                    data = json.loads(message['data'])
                    profileid = data.get('profileid')
                    srcip = profileid.split(self.separator)[1]
                    twid = data.get('twid')
                    type_detection = data.get(
                        'type_detection'
                    )   # example: dstip srcip dport sport dstdomain
                    detection_info = data.get(
                        'detection_info'
                    )   # example: ip, port, inTuple, outTuple, domain
                    type_evidence = data.get(
                        'type_evidence'
                    )   # example: PortScan, ThreatIntelligence, etc..
                    description = data.get('description')
                    timestamp = data.get('stime')
                    uid = data.get('uid')
                    # tags = data.get('tags', False)
                    confidence = data.get('confidence', False)
                    threat_level = data.get('threat_level', False)
                    category = data.get('category', False)
                    conn_count = data.get('conn_count', False)
                    port = data.get('port', False)
                    proto = data.get('proto', False)
                    source_target_tag = data.get('source_target_tag', False)
                    evidence_ID = data.get('ID', False)
                    flow = __database__.get_flow(profileid, twid, uid)

                    # FP whitelisted alerts happen when the db returns an evidence
                    # that isn't processed in this channel, in the tw_evidence below
                    # to avoid this, we only alert on processed evidence
                    __database__.mark_evidence_as_processed(profileid, twid, evidence_ID)

                    # Ignore alert if IP is whitelisted
                    if flow and self.whitelist.is_whitelisted_evidence(
                        srcip, detection_info, type_detection, description
                    ):
                        __database__.cache_whitelisted_evidence_ID(evidence_ID)
                        # Modules add evidence to the db before reaching this point, now
                        # remove evidence from db so it could be completely ignored
                        __database__.deleteEvidence(
                            profileid, twid, evidence_ID
                        )
                        continue

                    # Format the time to a common style given multiple type of time variables
                    # flow_datetime = utils.format_timestamp(timestamp)
                    flow_datetime = utils.convert_format(timestamp, 'iso')

                    # prepare evidence for text log file
                    evidence = self.format_evidence_string(
                        profileid,
                        twid,
                        srcip,
                        type_evidence,
                        type_detection,
                        detection_info,
                        description,
                    )
                    # prepare evidence for json log file
                    IDEA_dict = utils.IDEA_format(
                        srcip,
                        type_evidence,
                        type_detection,
                        detection_info,
                        description,
                        confidence,
                        category,
                        conn_count,
                        source_target_tag,
                        port,
                        proto,
                        evidence_ID
                    )

                    # to keep the alignment of alerts.json ip + hostname combined should take no more than 26 chars
                    alert_to_log = (
                        f'{flow_datetime}: Src IP {srcip:26}. {evidence}'
                    )
                    # sometimes slips tries to get the hostname of a profile before ip_info stores it in the db
                    # there's nothing we can do about it
                    hostname = __database__.get_hostname_from_profile(
                        profileid
                    )
                    if hostname:
                        srcip = f'{srcip} ({hostname})'
                        # fill the rest of the 26 characters with spaces to keep the alignment
                        srcip = f'{srcip}{" "*(26-len(srcip))}'
                        alert_to_log = (
                            f'{flow_datetime}: Src IP {srcip}. {evidence}'
                        )
                    # Add the evidence to the log files
                    self.addDataToLogFile(alert_to_log)
                    # add to alerts.json
                    if self.is_first_alert and branch_info != False:
                        # only add commit and hash to the firs alert in alerts.json
                        self.is_first_alert = False
                        IDEA_dict.update(
                            {
                                'commit': commit,
                                'branch': branch
                            }
                        )
                    self.addDataToJSONFile(IDEA_dict)
                    self.add_to_log_folder(IDEA_dict)
                    __database__.set_evidence_for_profileid(IDEA_dict)
                    __database__.publish('report_to_peers', json.dumps(data))

                    #
                    # Analysis of evidence for blocking or not
                    # This is done every time we receive 1 new evidence
                    #
                    tw_evidence = self.get_evidence_for_tw(profileid, twid)

                    # Important! It may happen that the evidence is not related to a profileid and twid.
                    # For example when the evidence is on some src IP attacking our home net, and we are not creating
                    # profiles for attackers
                    if tw_evidence:
                        # self.print(f'Evidence: {tw_evidence}. Profileid {profileid}, twid {twid}')

                        # The accumulated threat level is for all the types of evidence for this profile
                        accumulated_threat_level = self.get_accumulated_threat_level(tw_evidence)

                        ID = self.get_last_evidence_ID(tw_evidence)

                        # This is the part to detect if the accumulated evidence was enough for generating a detection
                        # The detection should be done in attacks per minute. The parameter in the configuration
                        # is attacks per minute
                        # So find out how many attacks corresponds to the width we are using
                        if (
                            accumulated_threat_level
                            >= self.detection_threshold_in_this_width
                        ):
                            if not __database__.checkBlockedProfTW(
                                profileid, twid
                            ):
                                # store the alert in our database
                                # the alert ID is profileid_twid + the ID of the last evidence causing this alert
                                alert_ID = f'{profileid}_{twid}_{ID}'
                                __database__.set_evidence_causing_alert(
                                    profileid,
                                    twid,
                                    alert_ID,
                                    self.IDs_causing_an_alert
                                )
                                __database__.publish('new_alert', alert_ID)

                                self.send_to_exporting_module(tw_evidence)

                                # print the alert
                                alert_to_print = (
                                    self.format_evidence_causing_this_alert(
                                        tw_evidence,
                                        profileid,
                                        twid,
                                        flow_datetime,
                                    )
                                )
                                self.print(f'{alert_to_print}', 1, 0)

                                # alerts.json should only contain alerts in idea format,
                                # blocked srcips should only be printed in alerts.log
                                # self.addDataToJSONFile(blocked_srcip_dict)

                                if self.popup_alerts:
                                    # remove the colors from the alerts before printing
                                    alert_to_print = (
                                        alert_to_print.replace(Fore.RED, '')
                                        .replace(Fore.CYAN, '')
                                        .replace(Style.RESET_ALL, '')
                                    )
                                    self.notify.show_popup(alert_to_print)

                                if self.decide_blocking(profileid):
                                    self.mark_as_blocked(
                                        profileid,
                                        twid,
                                        flow_datetime,
                                        accumulated_threat_level
                                    )

                message = __database__.get_message(self.c2)
                if utils.is_msg_intended_for(message, 'new_blame'):
                    data = message['data']
                    try:
                        data = json.loads(data)
                    except json.decoder.JSONDecodeError:
                        self.print(
                            'Error in the report received from p2ptrust module'
                        )
                        continue
                    # The available values for the following variables are defined in go_director

                    # available key types: "ip"
                    key_type = data['key_type']

                    # if the key type is ip, the ip is validated
                    key = data['key']

                    # available evaluation types: 'score_confidence'
                    evaluation_type = data['evaluation_type']

                    # this is the score_confidence received from the peer
                    evaluation = data['evaluation']
                    # {"key_type": "ip", "key": "1.2.3.40",
                    # "evaluation_type": "score_confidence",
                    # "evaluation": { "score": 0.9, "confidence": 0.6 }}
                    ip_info = {
                        'p2p4slips': evaluation
                    }
                    ip_info['p2p4slips'].update({'ts': time.time()})
                    __database__.store_blame_report(key, evaluation)

                    blocking_data = {
                        'ip': key,
                        'block': True,
                        'to': True,
                        'from': True,
                        'block_for': self.width * 2,  # block for 2 timewindows
                    }
                    blocking_data = json.dumps(blocking_data)
                    __database__.publish('new_blocking', blocking_data)

            except KeyboardInterrupt:
                self.shutdown_gracefully()
                # self.outputqueue.put('01|evidence|[Evidence] Stopping the Evidence Process')
                return True
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.outputqueue.put(
                    f'01|[Evidence] Error in the Evidence Process line {exception_line}'
                )
                self.outputqueue.put('01|[Evidence] {}'.format(type(inst)))
                self.outputqueue.put('01|[Evidence] {}'.format(inst))
                return True
