from flask import Blueprint
from flask import Flask, render_template, request
import json
from collections import defaultdict
from datetime import datetime
from database.database import __database__
from database.signals import message_sent

analysis = Blueprint('analysis', __name__, static_folder='static', static_url_path='/analysis/static',
                     template_folder='templates')


# ----------------------------------------
# HELPER FUNCTIONS
# ----------------------------------------
def ts_to_date(ts, seconds=False):
    if seconds:
        return datetime.fromtimestamp(ts).strftime('%Y/%m/%d %H:%M:%S.%f')
    return datetime.fromtimestamp(ts).strftime('%Y/%m/%d %H:%M:%S')


def get_all_tw_with_ts(profileid):
    tws = __database__.db.zrange("tws" + profileid, 0, -1, withscores=True)
    dict_tws = defaultdict(dict)

    for tw_tuple in tws:
        tw_n = tw_tuple[0]
        tw_ts = tw_tuple[1]
        tw_date = ts_to_date(tw_ts)
        dict_tws[tw_n]["tw"] = tw_n
        dict_tws[tw_n]["name"] = "TW" + " " + tw_n.split("timewindow")[1] + ":" + tw_date
        dict_tws[tw_n]["blocked"] = False  # needed to color profiles
    return dict_tws


def get_ip_info(ip):
    """
    Retrieve IP information from database
    :param ip: active IP
    :return: all data about the IP in database
    """
    data = {'geocountry': "-", 'asnorg': "-", 'reverse_dns': "-", "threat_intel": "-", "url": "-", "down_file": "-",
            "ref_file": "-",
            "com_file": "-"}
    ip_info = __database__.cachedb.hget('IPsInfo', ip)
    if ip_info:
        ip_info = json.loads(ip_info)
        # Hardcoded decapsulation due to the complexity of data in side. Ex: {"asn":{"asnorg": "CESNET", "timestamp": 0.001}}
        geocountry = ip_info.get('geocountry', '-')
        asn = ip_info.get('asn', False)
        asnorg = [asn.get('asnorg', '-') if asn else '-']
        reverse_dns = ip_info.get('reverse_dns', '-')

        threatintel = ip_info.get('threatintelligence', False)
        threatintel_info = [threatintel.get('description', '-') + "," + threatintel.get('threat_level',
                                                                                        '-') + " threat level" if threatintel else '-']

        vt_scores = ip_info.get("VirusTotal", False)
        url, down_file, ref_file, com_file = '-', '-', '-', '-'
        if vt_scores:
            url = vt_scores.get("URL", "-")
            down_file = vt_scores.get("down_file", "-")
            ref_file = vt_scores.get("ref_file", "-")
            com_file = vt_scores.get("com_file", "-")

        data = {'geocountry': geocountry, 'asnorg': asnorg,
                'reverse_dns': reverse_dns,
                'threat_intel': threatintel_info, "url": url,
                "down_file": down_file, "ref_file": ref_file,
                "com_file": com_file}
    return data


# ----------------------------------------
#
# ----------------------------------------


# ----------------------------------------
# ROUTE FUNCTIONS
# ----------------------------------------
@analysis.route("/profiles_tws")
def set_profile_tws():
    '''
    Set profiles and their timewindows into the tree. Blocked are highligted in red.
    :return: (profile, [tw, blocked], blocked)
    '''

    profiles_dict = dict()
    data = []

    # Fetch profiles
    profiles = __database__.db.smembers('profiles')
    for profileid in profiles:
        profile_word, profile_ip = profileid.split("_")
        profiles_dict[profile_ip] = False

    # Fetch blocked profiles
    blockedProfileTWs = __database__.db.hgetall('BlockedProfTW')
    if blockedProfileTWs:
        for blocked in blockedProfileTWs.keys():
            profile_word, blocked_ip = blocked.split("_")
            profiles_dict[blocked_ip] = True

    # Set all profiles
    for profile_ip, blocked_state in profiles_dict.items():
        data.append({"profile": profile_ip, "blocked": blocked_state})

    return {
        'data': data
    }


@analysis.route("/info/<ip>")
def set_ip_info(ip):
    '''
    Set info about the ip in route /info/<ip> (geocountry, asn, TI)
    :param ip: active IP
    :return: information about IP in database
    '''
    ip_info = get_ip_info(ip)
    ip_info["ip"] = ip
    data = [ip_info]

    return {
        'data': data
    }


@analysis.route("/tws/<profileid>")
def set_tws(profileid):
    '''
    Set timewindows for selected profile
    :return:
    '''

    data = []

    # Fetch all profile TWs
    tws = get_all_tw_with_ts("profile_" + profileid)

    # Fetch blocked tws
    blockedTWs = __database__.db.hget('BlockedProfTW', "profile_" + profileid)
    if blockedTWs:
        blockedTWs = json.loads(blockedTWs)

        for tw in blockedTWs:
            tws[tw]['blocked'] = True

    for tw_key, tw_value in tws.items():
        data.append({"tw": tw_value["tw"], "name": tw_value["name"], "blocked": tw_value["blocked"]})

    return {
        "data": data
    }


@analysis.route("/intuples/<profile>/<timewindow>")
def set_intuples(profile, timewindow):
    """
    Set intuples of a chosen profile and timewindow.
    :param profile: active profile
    :param timewindow: active timewindow
    :return: (tuple, string, ip_info)
    """
    data = []
    intuples = __database__.db.hget("profile_" + profile + '_' + timewindow, 'InTuples')
    if intuples:
        intuples = json.loads(intuples)
        for key, value in intuples.items():
            ip, port, protocol = key.split("-")
            ip_info = get_ip_info(ip)

            outtuple_dict = dict()
            outtuple_dict.update({'tuple': key, 'string': value[0]})
            outtuple_dict.update(ip_info)
            data.append(outtuple_dict)

    return {
        'data': data
    }

@analysis.route("/outtuples/<profile>/<timewindow>")
def set_outtuples(profile, timewindow):
    """
    Set outtuples of a chosen profile and timewindow.
    :param profile: active profile
    :param timewindow: active timewindow
    :return: (tuple, key, ip_info)
    """

    data = []
    outtuples = __database__.db.hget("profile_" + profile + '_' + timewindow, 'OutTuples')
    if outtuples:
        outtuples = json.loads(outtuples)

        for key, value in outtuples.items():
            ip, port, protocol = key.split("-")
            ip_info = get_ip_info(ip)
            outtuple_dict = dict()
            outtuple_dict.update({'tuple': key, 'string': value[0]})
            outtuple_dict.update(ip_info)
            data.append(outtuple_dict)

    return {
        'data': data
    }


@analysis.route("/timeline_flows/<profile>/<timewindow>")
def set_timeline_flows(profile, timewindow):
    """
    Set timeline flows of a chosen profile and timewindow.
    :return: list of timeline flows as set initially in database
    """
    data = []
    timeline_flows = __database__.db.hgetall("profile_" + profile + "_" + timewindow + "_flows")
    if timeline_flows:
        for key, value in timeline_flows.items():
            value = json.loads(value)

            # convert timestamp to date
            timestamp = value["ts"]
            dt_obj = ts_to_date(timestamp, seconds=True)
            value["ts"] = dt_obj

            # limit duration decimals
            duration = float(value["dur"])
            value["dur"] = "{:.5f}".format(duration)

            data.append(value)

    return {
        'data': data
    }


@analysis.route("/timeline/<profile>/<timewindow>")
# @analysis.route("/timeline/<profile>/<timewindow>/<search_filter>")
def set_timeline(profile, timewindow, search_filter=""):
    """
    Set timeline data of a chosen profile and timewindow
    :return: list of timeline as set initially in database
    """
    data = []

    timeline = __database__.db.zrange("profile_" + profile + "_" + timewindow + "_timeline", 0, -1)
    if timeline:

        search_filter = search_filter.strip()
        search = True if search_filter else False
        reverse = False
        if search and "!" in search_filter:
            search_filter = search_filter.replace("!", "")
            reverse = True

        for flow in timeline:
            flow = json.loads(flow)

            # TODO: check this logic
            if flow["preposition"] == "from":
                temp = flow["saddr"]
                flow["daddr"] = temp

            # search
            if not search:
                data.append(flow)
            else:
                value_is_present = False

                # partial search in each flow key
                for v in flow.values():
                    if search_filter.lower() in str(v).lower():
                        value_is_present = True
                        break

                if (not reverse and value_is_present) or (reverse and not value_is_present):
                    data.append(flow)

    return {
        'data': data
    }


@analysis.route("/alerts/<profile>/<timewindow>")
def set_alerts(profile, timewindow):
    """
    Set alerts for chosen profile and timewindow
    """
    data = []
    profile = "profile_" + profile
    alerts = __database__.db.hget("alerts", profile)

    if alerts:
        alerts = json.loads(alerts)
        alerts_tw = alerts.get(timewindow, dict())
        tws = get_all_tw_with_ts(profile)
        evidences = __database__.db.hget("evidence" + profile, timewindow)
        if evidences:
            evidences = json.loads(evidences)

        for alert_ID, evidence_ID_list in alerts_tw.items():
            evidence_count = len(evidence_ID_list)
            alert_description = json.loads(evidences[alert_ID])
            alert_timestamp = alert_description["stime"]
            if not isinstance(alert_timestamp, str):  # add check if the timestamp is a string
                alert_timestamp = ts_to_date(alert_description["stime"], seconds=True)
            profile_ip = profile.split("_")[1]
            tw_name = tws[timewindow]["name"]

            data.append(
                {"alert": alert_timestamp, "alert_id": alert_ID, "profileid": profile_ip, "timewindow": tw_name,
                 "evidence_count": evidence_count})
    return {"data": data}


@analysis.route("/evidence/<profile>/<timewindow>/<alert_id>")
def set_evidence(profile, timewindow, alert_id):
    """
    Set evidence table for the pressed alert in chosem profile and timewindow
    """

    data = []
    alerts = __database__.db.hget("alerts", "profile_" + profile)

    if alerts:
        alerts = json.loads(alerts)
        alerts_tw = alerts[timewindow]
        evidence_ID_list = alerts_tw[alert_id]
        evidences = __database__.db.hget("evidence" + "profile_" + profile, timewindow)
        evidences = json.loads(evidences)

        for evidence_ID in evidence_ID_list:
            temp_evidence = json.loads(evidences[evidence_ID])
            if "source_target_tag" not in temp_evidence:
                temp_evidence["source_target_tag"] = "-"
            data.append(temp_evidence)
    return {"data": data}


@analysis.route("/evidence/<profile>/<timewindow>/")
def set_evidence_general(profile, timewindow):
    """
    Set an analysis tag with general evidence
    :param profile:
    :param timewindow:
    :return: {"data": data} where data is a list of evidences
    """
    data = []
    evidence = __database__.db.hget("evidence"+"profile_" + profile, timewindow)
    if evidence:
        evidence = json.loads(evidence)
        for id, content in evidence.items():
            content = json.loads(content)
            if "source_target_tag" not in content:
                content["source_target_tag"] = "-"
            data.append(content)
    return {"data": data}


@analysis.route('/')
def index():
    return render_template('analysis.html', title='Slips')
