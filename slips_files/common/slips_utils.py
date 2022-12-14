import hashlib
from datetime import datetime, timezone, timedelta
import validators
from git import Repo
import socket
import subprocess
import json
import time
import platform
import os
import sys
import ipaddress
import configparser


class Utils(object):
    name = 'utils'
    description = 'Common functions used by different modules of slips.'
    authors = ['Alya Gomaa']


    def __init__(self):
        self.home_network_ranges = (
            '192.168.0.0/16',
            '172.16.0.0/12',
            '10.0.0.0/8',
        )
        self.home_network_ranges = list(map(ipaddress.ip_network, self.home_network_ranges))
        self.supported_orgs = (
            'google',
            'microsoft',
            'apple',
            'facebook',
            'twitter',
        )
        self.home_networks = ('192.168.0.0', '172.16.0.0', '10.0.0.0')
        self.threat_levels = {
            'info': 0,
            'low': 0.2,
            'medium': 0.5,
            'high': 0.8,
            'critical': 1,
        }
        self.time_formats = (
            '%Y-%m-%dT%H:%M:%S.%f%z',
            '%Y-%m-%d %H:%M:%S.%f',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f%z',
            '%Y/%m/%d %H:%M:%S.%f%z',
            '%Y/%m/%d %H:%M:%S.%f',
            '%Y/%m/%d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S%z',
            "%Y-%m-%dT%H:%M:%S",
            '%Y-%m-%dT%H:%M:%S%z',
            '%Y/%m/%d-%H:%M:%S',
            '%Y-%m-%dT%H:%M:%S'

         )
        # this format will be used accross all modules and logfiles of slips
        self.alerts_format = '%Y/%m/%d %H:%M:%S.%f%z'

    def threat_level_to_string(self, threat_level: float):
        for str_lvl, int_value in self.threat_levels.items():
            if float(threat_level) <= int_value:
                return str_lvl



    def sanitize(self, string):
        """
        Sanitize strings taken from the user
        """
        string = string.replace(';', '')
        string = string.replace('\`', '')
        string = string.replace('&', '')
        string = string.replace('|', '')
        string = string.replace('$(', '')
        string = string.replace('\n', '')
        return string

    def detect_data_type(self, data):
        """Detects if incoming data is ipv4, ipv6, domain or ip range"""
        data = data.strip()
        try:
            ipaddress.ip_address(data)
            return 'ip'
        except (ipaddress.AddressValueError, ValueError):
            pass

        try:
            ipaddress.ip_network(data)
            return 'ip_range'
        except ValueError:
            pass

        if validators.md5(data):
            return 'md5'

        if validators.domain(data):
            return 'domain'

        # some ti files have / at the end of domains, remove it
        if data.endswith('/'):
            data = data[:-1]

        domain = data

        if domain.startswith('http://'):
            data = data[7:]
        elif domain.startswith('https://'):
            data = data[8:]

        if validators.domain(data):
            return 'domain'
        elif '/' in data:
            return 'url'

        if validators.sha256(data):
            return 'sha256'



    def drop_root_privs(self):
        """
        Drop root privileges if the module doesn't need them
        Shouldn't be called from __init__ because then, it affects the parent process too
        """

        if platform.system() != 'Linux':
            return
        try:
            # Get the uid/gid of the user that launched sudo
            sudo_uid = int(os.getenv('SUDO_UID'))
            sudo_gid = int(os.getenv('SUDO_GID'))
        except TypeError:
            # env variables are not set, you're not root
            return
        # Change the current process’s real and effective uids and gids to that user
        # -1 means value is not changed.
        os.setresgid(sudo_gid, sudo_gid, -1)
        os.setresuid(sudo_uid, sudo_uid, -1)
        return

    def timeit(method):
        def timed(*args, **kw):
            ts = time.time()
            result = method(*args, **kw)
            te = time.time()
            if 'log_time' in kw:
                name = kw.get('log_name', method.__name__.upper())
                kw['log_time'][name] = int((te - ts) * 1000)
            else:
                print(
                    f'\t\033[1;32;40mFunction {method.__name__}() took {(te - ts) * 1000:2.2f}ms\033[00m'
                )
            return result

        return timed


    def convert_format(self, ts, required_format: str):
        """
        Detects and converts the given ts to the given format
        :param required_format: can be any format like '%Y/%m/%d %H:%M:%S.%f' or 'unixtimestamp', 'iso'
        """
        given_format = self.define_time_format(ts)
        if given_format == required_format:
            return ts

        if given_format == 'datetimeobj':
            datetime_obj = ts
        else:
            datetime_obj = self.convert_to_datetime(ts)

        # convert to the req format
        if required_format == 'unixtimestamp':
            result = datetime_obj.timestamp()
        elif required_format == 'iso':
            result = datetime_obj.astimezone().isoformat()
        else:
            result = datetime_obj.strftime(required_format)

        return result

    def is_datetime_obj(self, ts):
        """
        checks if the given ts is a datetime obj
        """
        try:
            ts.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
            return True
        except AttributeError:
            return False

    def convert_to_datetime(self, ts):
        if self.is_datetime_obj(ts):
            return ts

        given_format = self.define_time_format(ts)

        if given_format == 'unixtimestamp':
            datetime_obj = datetime.fromtimestamp(float(ts))
        else:
            datetime_obj = datetime.strptime(ts, given_format)
        return datetime_obj


    def define_time_format(self, time: str) -> str:

        if self.is_datetime_obj(time):
            return 'datetimeobj'

        try:
            # Try unix timestamp in seconds.
            datetime.fromtimestamp(float(time))
            time_format = 'unixtimestamp'
            return time_format
        except ValueError:
            pass


        for time_format in self.time_formats:
            try:
                datetime.strptime(time, time_format)
                return time_format
            except ValueError:
                pass

        return False

    def to_delta(self, time_in_seconds):
        return timedelta(seconds=int(time_in_seconds))

    def get_own_IPs(self) -> list:
        """
        Returns a list of our local and public IPs
        """
        if '-i' not in sys.argv:
            # this method is only valid when running on an interface
            return []

        IPs = []
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            IPs.append(s.getsockname()[0])
        except Exception:
            IPs.append('127.0.0.1')
        finally:
            s.close()

        # get public ip
        command = f'curl -m 5 -s http://ipinfo.io/json'
        result = subprocess.run(command.split(), capture_output=True)
        text_output = result.stdout.decode('utf-8').replace('\n', '')
        if not text_output or 'Connection timed out' in text_output:
            return IPs

        public_ip = json.loads(text_output)['ip']
        IPs.append(public_ip)
        return IPs

    def convert_to_mb(self, bytes):
        return int(bytes)/(10**6)

    def is_ignored_ip(self, ip) -> bool:
        """
        This function checks if an IP is a special list of IPs that
        should not be alerted for different reasons
        """
        ip_obj = ipaddress.ip_address(ip)
        # Is the IP multicast, private? (including localhost)
        # local_link or reserved?
        # The broadcast address 255.255.255.255 is reserved.
        if (
            ip_obj.is_multicast
            or ip_obj.is_private
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or '.255' in ip_obj.exploded
        ):
            return True
        return False

    def get_hash_from_file(self, filename):
        """
        Compute the sha256 hash of a file
        """
        # The size of each read from the file
        BLOCK_SIZE = 65536
        # Create the hash object, can use something other
        # than `.sha256()` if you wish
        file_hash = hashlib.sha256()
        # Open the file to read it's bytes
        with open(filename, 'rb') as f:
            # Read from the file. Take in the amount declared above
            fb = f.read(BLOCK_SIZE)
            # While there is still data being read from the file
            while len(fb) > 0:
                # Update the hash
                file_hash.update(fb)
                # Read the next block from the file
                fb = f.read(BLOCK_SIZE)
        return file_hash.hexdigest()

    def is_msg_intended_for(self, message, channel):
        """
        Function to check
            1. If the given message is intended for this channel
            2. The msg has valid data
        """

        return (
            message
            and type(message['data']) == str
            and message['data'] != 'stop_process'
            and message['channel'] == channel
        )

    def get_branch_info(self):
        """
        Returns a tuple containing (commit,branch)
        """
        try:
            repo = Repo('.')
            # add branch name and commit
            branch = repo.active_branch.name
            commit = repo.active_branch.commit.hexsha
            return (commit, branch)
        except:
            # when in docker, we copy the repo instead of clone it so there's no .git files
            # we can't add repo metadata
            return False


    def get_time_diff(self, start_time: float, end_time: float, return_type='seconds') -> float:
        """
        Both times can be in any format
        returns difference in seconds
        :param return_type: can be seconds, minutes, hours or days
        """
        start_time = self.convert_to_datetime(start_time)
        end_time = self.convert_to_datetime(end_time)

        diff = str(end_time - start_time)
        # if there are days diff between the flows, diff will be something like 1 day, 17:25:57.458395
        try:
            # calculate the days difference
            diff_in_days = float(
                diff.split(', ')[0].split(' ')[0]
            )
            diff = diff.split(', ')[1]
        except (IndexError, ValueError):
            # no days different
            diff = diff.split(', ')[0]
            diff_in_days = 0

        diff_in_hrs, diff_in_mins, diff_in_seconds = [float(i) for i in diff.split(':')]


        diff_in_seconds = diff_in_seconds  + (24 * diff_in_days * 60 + diff_in_hrs * 60 + diff_in_mins)*60
        units = {
            'days': diff_in_seconds /(60*60*24),
            'hours':diff_in_seconds/(60*60),
            'minutes': diff_in_seconds/60,
            'seconds':  diff_in_seconds
        }

        return units[return_type]


    def IDEA_format(
        self,
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
        evidence_id
    ):
        """
        Function to format our evidence according to Intrusion Detection Extensible Alert (IDEA format).
        Detailed explanation of IDEA categories: https://idea.cesnet.cz/en/classifications
        """
        IDEA_dict = {
            'Format': 'IDEA0',
            'ID': evidence_id,
            # both times represet the time of the detection, we probably don't need flow_datetime
            'DetectTime': datetime.now(timezone.utc).isoformat(),
            'EventTime': datetime.now(timezone.utc).isoformat(),
            'Category': [category],
            'Confidence': confidence,
            'Source': [{}],
        }

        # is the srcip ipv4/ipv6 or mac?
        if validators.ipv4(srcip):
            IDEA_dict['Source'][0].update({'IP4': [srcip]})
        elif validators.ipv6(srcip):
            IDEA_dict['Source'][0].update({'IP6': [srcip]})
        elif validators.mac_address(srcip):
            IDEA_dict['Source'][0].update({'MAC': [srcip]})

        # update the srcip description if specified in the evidence
        if source_target_tag:   # https://idea.cesnet.cz/en/classifications#sourcetargettagsourcetarget_classification
            # for example: this will be 'Botnet' in case of C&C alerts not C&C,
            # because it describes the source ip
            IDEA_dict['Source'][0].update({'Type': [source_target_tag]})

        # When someone communicates with C&C, both sides of communication are
        # sources, differentiated by the Type attribute, 'C&C' or 'Botnet'
        if type_evidence == 'Command-and-Control-channels-detection':
            # get the destination IP
            dstip = description.split('destination IP: ')[1].split(' ')[0]

            if validators.ipv4(dstip):
                ip_version = 'IP4'
            elif validators.ipv6(dstip):
                ip_version = 'IP6'

            IDEA_dict['Source'].append({ip_version: [dstip], 'Type': ['CC']})

        # some evidence have a dst ip
        if 'dstip' in type_detection or 'dip' in type_detection:
            # is the dstip ipv4/ipv6 or mac?
            if validators.ipv4(detection_info):
                IDEA_dict['Target'] = [{'IP4': [detection_info]}]
            elif validators.ipv6(detection_info):
                IDEA_dict['Target'] = [{'IP6': [detection_info]}]
            elif validators.mac_address(detection_info):
                IDEA_dict['Target'] = [{'MAC': [detection_info]}]

            # try to extract the hostname/SNI/rDNS of the dstip form the description if available
            hostname = False
            try:
                hostname = description.split('rDNS: ')[1]
            except IndexError:
                pass
            try:
                hostname = description.split('SNI: ')[1]
            except IndexError:
                pass
            if hostname:
                IDEA_dict['Target'][0].update({'Hostname': [hostname]})
            # update the dstip description if specified in the evidence
            if source_target_tag:
                IDEA_dict['Target'][0].update({'Type': [source_target_tag]})

        elif 'domain' in type_detection:
            # the ioc is a domain
            target_info = {'Hostname': [detection_info]}
            IDEA_dict['Target'] = [target_info]

            # update the dstdomain description if specified in the evidence
            if source_target_tag:
                IDEA_dict['Target'][0].update({'Type': [source_target_tag]})

        # add the port/proto
        # for all alerts, the srcip is in IDEA_dict['Source'][0] and the dstip is in IDEA_dict['Target'][0]
        # for alert that only have a source, this is the port/proto of the source ip
        key = 'Source'
        idx = 0   # this idx is used for selecting the right dict to add port/proto

        if 'Target' in IDEA_dict:
            # if the alert has a target, add the port/proto to the target(dstip)
            key = 'Target'
            idx = 0

        # for C&C alerts IDEA_dict['Source'][0] is the Botnet aka srcip and IDEA_dict['Source'][1] is the C&C aka dstip
        if type_evidence == 'Command-and-Control-channels-detection':
            # idx of the dict containing the dstip, we'll use this to add the port and proto to this dict
            key = 'Source'
            idx = 1

        if port:
            IDEA_dict[key][idx].update({'Port': [int(port)]})
        if proto:
            IDEA_dict[key][idx].update({'Proto': [proto.lower()]})

        # add the description
        attachment = {
            'Attach': [
                {
                    'Content': description,
                    'ContentType': 'text/plain',
                }
            ]
        }
        IDEA_dict.update(attachment)

        # only evidence of type scanning have conn_count
        if conn_count:
            IDEA_dict.update({'ConnCount': conn_count})

        if 'MaliciousDownloadedFile' in type_evidence:
            IDEA_dict.update(
                {
                    'Attach': [
                        {
                            'Type': ['Malware'],
                            'Hash': [f'md5:{detection_info}'],
                            'Size': int(
                                description.split('size:')[1].split('from')[0]
                            ),
                        }
                    ]
                }
            )

        return IDEA_dict

    def timing(f):
        """Function to measure the time another function takes."""

        def wrap(*args):
            time1 = time.time()
            ret = f(*args)
            time2 = time.time()
            print('[DB] Function took {:.3f} ms'.format((time2 - time1) * 1000.0))
            return ret

        return wrap

utils = Utils()
