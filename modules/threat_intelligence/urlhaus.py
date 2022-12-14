# Must imports
from slips_files.common.slips_utils import utils
from slips_files.core.database.database import __database__

# Your imports
import json
import requests

URLHAUS_BASE_URL = 'https://urlhaus-api.abuse.ch/v1'

class URLhaus():
    name = 'URLhaus'
    description = 'URLhaus lookups of URLs and hashes'
    authors = ['Alya Gomaa']

    def __init__(self):
        self.create_urlhaus_session()


    def create_urlhaus_session(self):
        self.urlhaus_session = requests.session()
        self.urlhaus_session.verify = True


    def make_urlhaus_request(self, to_lookup: dict):
        """
        :param to_lookup: dict with {ioc_type: ioc}
        supported ioc types are md5_hash and url
        """
        ioc_type = next(iter(to_lookup))
        uri = 'url' if ioc_type=='url' else 'payload'
        try:
            urlhaus_api_response = self.urlhaus_session.post(
                f'{URLHAUS_BASE_URL}/{uri}/',
                to_lookup,
                headers=self.urlhaus_session.headers
            )
            return urlhaus_api_response
        except requests.exceptions.ConnectionError:
            self.create_urlhaus_session()


    def parse_urlhaus_url_response(self, response, url):
        threat = response['threat']
        url_status = response['url_status']
        description = f"Connecting to a malicious URL {url}. Detected by: URLhaus " \
                      f"threat: {threat}, URL status: {url_status}"
        try:
            tags = " ".join(tag for tag in response['tags'])
            description += f', tags: {tags}'
        except TypeError:
            # no tags available
            tags = ''

        try:
            payloads: dict = response['payloads'][0]
            file_type = payloads.get("file_type", "")
            file_name = payloads.get("filename", "")
            md5 = payloads.get("response_md5", "")
            signature = payloads.get("signature", "")

            description += f', the file hosted in this url is of type: {file_type},' \
                           f' filename: {file_name} md5: {md5} signature: {signature}. '

            # if we dont have a percentage repprted by vt, we will set out own
            # tl in set_evidence_malicious_url() function
            threat_level = False
            virustotal_info = payloads.get("virustotal", "")
            if virustotal_info:
                virustotal_percent = virustotal_info.get("percent", "")
                threat_level = virustotal_percent
                # virustotal_result = virustotal_info.get("result", "")
                # virustotal_result.replace('\',''')
                description += f'and was marked by {virustotal_percent}% of virustotal\'s AVs as malicious'

        except (KeyError, IndexError):
            # no payloads available
            pass


        info = {
            # get all the blacklists where this ioc is listed
            'source': 'URLhaus',
            'url': url,
            'description': description,
            'threat_level': threat_level,
            'tags': tags,
        }
        return info

    def parse_urlhaus_md5_response(self, response, md5):
        info = {}
        file_type = response.get("file_type", "")
        file_name = response.get("filename", "")
        file_size = response.get("file_size", "")
        tags = response.get("signature", "")
        # urls is a list of urls hosting this file
        # urls: list= response.get("urls")
        virustotal_info: dict = response.get("virustotal", "")

        threat_level = False
        if virustotal_info:
            virustotal_percent = virustotal_info.get("percent", "")
            threat_level = virustotal_percent
            # virustotal_result = virustotal_info.get("result", "")
            # virustotal_result.replace('\',''')


        info = {
            # get all the blacklists where this ioc is listed
            'blacklist': 'URLhaus',
            'threat_level': threat_level,
            'tags': tags,
            'file_type': file_type,
            'file_name': file_name,

        }
        return info

    def urlhaus_lookup(self, ioc, type_of_ioc: str):
        """
        Supports URL lookups only
        :param ioc: can be domain or ip
        :param type_of_ioc: can be md5_hash, or url
        """

        # available types at urlhaus are url, md5
        urlhaus_data = {
            type_of_ioc: ioc
        }
        urlhaus_api_response = self.make_urlhaus_request(urlhaus_data)

        if not urlhaus_api_response:
            return

        if urlhaus_api_response.status_code != 200:
            return

        response: dict = json.loads(urlhaus_api_response.text)

        if(
            response['query_status'] == 'no_results'
            or response['query_status'] == 'invalid_url'
        ):
            # no response or empty response
            return

        if type_of_ioc == 'url':
            info = self.parse_urlhaus_url_response(response, ioc)
            return info

        elif type_of_ioc == 'md5_hash':
            info = self.parse_urlhaus_md5_response(response, ioc)
            return info

    def set_evidence_malicious_hash(self, file_info: dict):
        type_detection = 'md5'
        category = 'Malware'
        type_evidence = 'MaliciousDownloadedFile'
        detection_info = file_info["md5"]
        threat_level = file_info["threat_level"]
        daddr = file_info["daddr"]
        ip_identification = __database__.getIPIdentification(daddr)
        # we have more info about the downloaded file
        # so we need a more detailed description
        description = f"Malicious downloaded file: {file_info['md5']}. " \
                      f"size: {file_info['size']}" \
                      f"from IP: {file_info['daddr']} {ip_identification}." \
                      f"file name: {file_info['file_name']} " \
                      f"file type: {file_info['file_type']} " \
                      f"tags: {file_info['tags']}. by URLhaus." \

        if threat_level:
            # threat level here is the vt percentage from urlhaus
            description += f" virustotal score: {threat_level}% malicious"
            threat_level = threat_level/100
        else:
            threat_level = 0.8

        confidence = 0.7

        __database__.setEvidence(
            type_evidence,
            type_detection,
            detection_info,
            threat_level,
            confidence,
            description,
            file_info["ts"],
            category,
            profileid=file_info["profileid"],
            twid=file_info["twid"],
            uid=file_info["uid"],
        )

    def set_evidence_malicious_url(
            self,
            url_info,
            uid,
            timestamp,
            profileid,
            twid
    ):
        """
        :param url_info: dict with source, description, therat_level, and tags of url
        """
        threat_level = url_info['threat_level']
        detection_info = url_info['url']
        description = url_info['description']

        confidence = 0.7

        if not threat_level:
            threat_level = 'medium'
        else:
            # convert percentage reported by urlhaus (virustotal) to
            # a valid slips confidence
            try:
                threat_level = int(threat_level)/100
                threat_level = utils.threat_level_to_string(threat_level)
            except ValueError:
                threat_level = 'medium'


        type_detection = 'url'
        category = 'Malware'
        type_evidence = 'MaliciousURL'

        __database__.setEvidence(
            type_evidence,
            type_detection,
            detection_info,
            threat_level,
            confidence,
            description,
            timestamp,
            category,
            profileid=profileid,
            twid=twid,
            uid=uid,
        )