"""Unit test for modules/ip_info/ip_info.py"""
from ..modules.ip_info.ip_info import Module
from ..modules.ip_info.asn_info import ASN
import asyncio
import pytest

def do_nothing(*args):
    """Used to override the print function because using the self.print causes broken pipes"""
    pass


def create_ip_info_instance(outputQueue):
    """Create an instance of ip_info.py
    needed by every other test in this file"""
    ip_info = Module(outputQueue, 6380)
    # override the self.print function to avoid broken pipes
    ip_info.print = do_nothing
    return ip_info


def create_ASN_Info_instance():
    """Create an instance of asn_info.py
    needed by every other test in this file"""
    ASN_Info = ASN()
    return ASN_Info


# ASN unit tests
def test_get_asn_info_from_geolite(database):
    ASN_info = create_ASN_Info_instance()
    # check an ip that we know is in the db
    assert ASN_info.get_asn_info_from_geolite('108.200.116.255') == {
        'asn': {'asnorg': 'ATT-INTERNET4'}
    }
    # test  asn info not found in geolite
    assert ASN_info.get_asn_info_from_geolite('0.0.0.0') == {
        'asn': {'asnorg': 'Unknown'}
    }


def test_get_asn_online(database):
    ASN_info = create_ASN_Info_instance()
    ip = '104.18.7.29'
    found_info = ASN_info.get_asn_online(ip)
    assert found_info != {'asn': {'asnorg': 'Unknown'}}, 'Connection Error'
    assert found_info['asn']['asnorg'] == 'AS13335 Cloudflare, Inc.', 'Server Error'

def test_cache_ip_range(database):
    ASN_info = create_ASN_Info_instance()
    assert ASN_info.cache_ip_range('8.8.8.8') == True


def test_get_cached_asn(database):
    ASN_info = create_ASN_Info_instance()
    database.set_asn_cache('AS123', '192.168.1.0/24')
    assert ASN_info.get_cached_asn('192.168.1.1') == 'AS123'


# RDNS unit tests


def test_get_rdns(outputQueue, database):
    ip_info = create_ip_info_instance(outputQueue)
    # check an ip that we know has a rdns
    assert ip_info.get_rdns('99.81.154.45') == {
        'reverse_dns': 'ec2-99-81-154-45.eu-west-1.compute.amazonaws.com'
    }
    # test  RDNS info not found
    assert ip_info.get_rdns('0.0.0.0') == False


# GEOIP unit tests


def test_get_geocountry(outputQueue, database):
    ip_info = create_ip_info_instance(outputQueue)
    # open the db we'll be using for this test
    ip_info.wait_for_dbs()
    assert ip_info.get_geocountry('153.107.41.230') == {
        'geocountry': 'Australia'
    }
    assert ip_info.get_geocountry('23.188.195.255') == {
        'geocountry': 'Unknown'
    }


# MAC vendor unit tests
def test_get_vendor_offline(outputQueue, database):
    ip_info = create_ip_info_instance(outputQueue)
    # open the db we'll be using for this test
    ip_info.wait_for_dbs()
    mac_addr = '08:00:27:7f:09:e1'
    profileid = 'profile_10.0.2.15'
    found_info = ip_info.get_vendor_offline(mac_addr, 'google.com', profileid)
    assert found_info != False
    assert found_info.lower() == 'PCS Systemtechnik GmbH'.lower()


def test_get_vendor_online(outputQueue, database):
    ip_info = create_ip_info_instance(outputQueue)
    mac_addr = '08:00:27:7f:09:e1'
    found_info = str(ip_info.get_vendor_online(mac_addr)).lower()
    assert found_info == 'Pcs Systemtechnik GmbH'.lower(), 'Error connecting to server'


def test_get_vendor(outputQueue, database):
    ip_info = create_ip_info_instance(outputQueue)
    # open the db we'll be using for this test
    ip_info.wait_for_dbs()
    profileid = 'profile_10.0.2.15'
    mac_addr = '08:00:27:7f:09:e1'
    host_name = 'FooBar-PC'
    mac_info = ip_info.get_vendor(mac_addr, host_name, profileid)
    assert mac_info != False
    assert mac_info['Vendor'].lower() == 'Pcs Systemtechnik GmbH'.lower()
