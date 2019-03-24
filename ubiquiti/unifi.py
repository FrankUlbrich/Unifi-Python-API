#!/usr/bin/env python3
""" Control a Unifi Controller via Python."""
from requests import Session
import json
import os
import re
from typing import Pattern, Dict, Union


class LoggedInException(Exception):
    """LoggedInException."""

    def __init__(self, *args, **kwargs):
        """Init function for LoggedInException."""
        super(LoggedInException, self).__init__(*args, **kwargs)


class API(object):
    """Unifi API for the Unifi Controller."""

    _login_data = {}
    _current_status_code = None

    def __init__(self, username: str="ubnt", password: str="ubnt", site: str="default", baseurl: str="https://unifi:8443", verify_ssl: bool=True):
        """
        Initiate the api with defaults if unset.

        :param username: cloudkey username
        :param password: cloudkey password
        :param site: name of site (https://unifi:8443/manage/site/$THIS)
        :param baseurl: controller URL
        :param verify_ssl: toggle check of ssl cert validity (warns on False)
        """
        self._login_data['username'] = username
        self._login_data['password'] = password
        self._site = site
        self._verify_ssl = verify_ssl
        self._baseurl = baseurl
        self._session = Session()

        if not verify_ssl and os.environ.get('IGNORE_SSL_WARNING', False):
            import warnings
            warnings.filterwarnings("ignore")  # Suppress SSL warnings

    def __enter__(self):
        """
        Contextmanager entry handle.

        :return: instance object of class
        """
        self.login()
        return self

    def __exit__(self, *args):
        """
        Contextmanager exit handle.

        :return: None
        """
        self.logout()

    def _check_status_code(self, code):
        status_codes = {400: "Invalid credentials",
                        401: "Invalid login, or login has expired",
                        403: "Current user not authorized to perform action"}
        if code == 401:
            try:
                self.login()
            except LoggedInException:
                raise LoggedInException(status_codes[code])
        elif code in status_codes:
            raise LoggedInException(status_codes[code])

    def _filter(self, filters: Dict[str, Union[str, Pattern]], data: list) -> list:
        """Apply a set of filters to data."""
        for term, value in filters.items():
            value_re = value if isinstance(value, Pattern) else re.compile(value)

            data = [x for x in data if term in x.keys() and re.fullmatch(value_re, x[term])]
        return data

    def login(self):
        """
        Log the user in.

        :return: None
        """
        self._current_status_code = self._session.post("{}/api/login".format(self._baseurl), data=json.dumps(self._login_data), verify=self._verify_ssl).status_code
        self._check_status_code(self._current_status_code)

    def logout(self):
        """
        Log the user out.

        :return: None
        """
        self._session.get("{}/logout".format(self._baseurl))
        self._session.close()

    def self(self) -> dict:
        """
        List data about the current caller.

        :return: A dict of information about the caller (see below)
        admin_id: 5bf09832e9875059b0390a9
        device_id: FC000390839999902
        email: none@none.com
        email_alert_enabled: True
        email_alert_grouping_delay: 60
        email_alert_grouping_enabled: True
        html_email_enabled: True
        is_local: True
        is_professional_installer: False
        is_super: False
        last_site_name: default
        name: monitoring
        requires_new_password: False
        super_site_permissions: ['API_STAT_DEVICE_ACCESS_SUPER_SITE_PENDING', 'API_WIDGET_OS_STATS']
        ui_settings: {'dashboardConfig': {'lastActiveDashboardId': '5bf09832e9875059b0390a9'}}
        """
        r = self._session.get("{}/api/self".format(self._baseurl, self._site, verify=self._verify_ssl), data="json={}")
        self._current_status_code = r.status_code
        self._check_status_code(self._current_status_code)

        data = r.json()['data']
        return data[0]

    def list_clients(self, filters: Dict[str, Union[str, Pattern]]=None, order_by: str=None) -> list:
        """
        List all available clients from the api.

        :param filters: dict of k/v pairs; string is compiled to regex
        :param order_by: order by a key; defaults to '_id'
        :return: A list of clients on the format of a dict
        """
        r = self._session.get("{}/api/s/{}/stat/sta".format(self._baseurl, self._site, verify=self._verify_ssl), data="json={}")
        self._current_status_code = r.status_code
        self._check_status_code(self._current_status_code)

        data = r.json()['data']

        if filters:
            _filter(filters, data)

        if order_by:
            data = sorted(data, key=lambda x: x[order_by] if order_by in x.keys() else x['_id'])

        return data

    def health(self) -> dict:
        """
        List site health information.

        :return: A dict of network health information (see below)
        num_adopted
        num_ap
        num_disabled
        num_disconnected
        num_guest
        num_iot
        num_pending
        num_user
        rx_bytes-r
        status
        subsystem
        tx_bytes-r
        """
        r = self._session.get("{}/api/s/{}/stat/health".format(self._baseurl, self._site, verify=False), data="json={}")
        self._current_status_code = r.status_code
        self._check_status_code(self._current_status_code)

        data = r.json()['data']

        return data[0]

    def info(self) -> dict:
        """
        List site information.

        :return: A dict of site information (see below for a sample)
        autobackup
        build
        cloudkey_update_version
        cloudkey_version
        data_retention_days
        debug_system
        eol_pending_device_count
        hostname
        https_port
        inform_port
        ip_addrs
        name
        timezone
        unifi_go_enabled
        update_available
        version
        """
        r = self._session.get("{}/api/s/{}/stat/sysinfo".format(self._baseurl, self._site, verify=False), data="json={}")
        self._current_status_code = r.status_code
        self._check_status_code(self._current_status_code)

        data = r.json()['data']

        return data[0]

    def events(self, filters: Dict[str, Union[str, Pattern]]=None, order_by: str=None) -> list:
        """
        List site events.

        :param filters: dict of k/v pairs; string is compiled to regex
        :param order_by: order by a key; defaults to '_id'
        :return: A list of events as dicts (see below for sample keys)
        app_proto
        datetime
        dest_ip
        dest_port
        event_type
        host
        key
        msg
        proto
        site_id
        src_ip
        src_mac
        src_port
        srcipCountry
        subsystem
        time
        """
        r = self._session.get("{}/api/s/{}/stat/event".format(self._baseurl, self._site, verify=self._verify_ssl), data="json={}")
        self._current_status_code = r.status_code
        self._check_status_code(self._current_status_code)

        data = r.json()['data']

        if filters:
            self._filter(filters)

        if order_by:
            data = sorted(data, key=lambda x: x[order_by] if order_by in x.keys() else x['_id'])

        return data

    def routes(self, filters: Dict[str, Union[str, Pattern]]=None, order_by: str=None) -> list:
        """
        List site routes.

        :param filters: dict of k/v pairs; string is compiled to regex
        :param order_by: order by a key; defaults to '_id'
        :return: A list of routes as dicts (see below for example data)
        nh: [{'intf': 'eth0',
              't': 'C>*'
            }]
        pfx: 192.168.1.0/24
        """
        r = self._session.get("{}/api/s/{}/stat/routing".format(self._baseurl, self._site, verify=self._verify_ssl), data="json={}")
        self._current_status_code = r.status_code
        self._check_status_code(self._current_status_code)

        data = r.json()['data']

        if filters:
            data = _filter(filters, data)

        if order_by:
            data = sorted(data, key=lambda x: x[order_by] if order_by in x.keys() else x['_id'])

        return data

    def port_forwarding(self, filters: Dict[str, Union[str, Pattern]]=None, order_by: str=None) -> list:
        """
        List forwarded ports.

        :param filters: dict of k/v pairs; string is compiled to regex
        :param order_by: order by a key; defaults to '_id'
        :return: A list of forwarded ports as dicts (see below)
        _id
        dst_port
        fwd
        fwd_port
        name
        proto
        site_id
        src
        """
        r = self._session.get("{}/api/s/{}/rest/portforward".format(self._baseurl, self._site, verify=self._verify_ssl), data="json={}")
        self._current_status_code = r.status_code
        self._check_status_code(self._current_status_code)

        data = r.json()['data']

        if filters:
            data = _filter(filters, data)

        if order_by:
            data = sorted(data, key=lambda x: x[order_by] if order_by in x.keys() else x['_id'])

        return data

    def list_aps(self, filters: Dict[str, Union[str, Pattern]]=None, order_by: str=None) -> list:
        """
        List nearby access points (and identify potential rogue APs).

        :param filters: dict of k/v pairs; string is compiled to regex
        :param order_by: order by a key; defaults to '_id'
        :return: A list of access_points as dicts (see below)
        _id
        age
        ap_mac
        band
        bssid
        bw
        center_freq
        channel
        essid
        freq
        is_adhoc
        is_rogue
        is_ubnt
        last_seen
        noise
        oui
        radio
        radio_name
        report_time
        rssi
        rssi_age
        security
        signal
        site_id
        """
        r = self._session.get("{}/api/s/{}/stat/rogueap".format(self._baseurl, self._site, verify=self._verify_ssl), data="json={}")
        self._current_status_code = r.status_code
        self._check_status_code(self._current_status_code)

        data = r.json()['data']

        if filters:
            data = _filter(filters, data)

        if order_by:
            data = sorted(data, key=lambda x: x[order_by] if order_by in x.keys() else x['_id'])

        return data

    def list_sites(self, verbose=False, filters: Dict[str, Union[str, Pattern]]=None, order_by: str=None) -> list:
        """
        Lists all sites on cloudkey.

        :param verbose: return more detailed information on each site
        :param filters: dict of k/v pairs; string is compiled to regex
        :param order_by: order by a key; defaults to '_id'
        :return: A list of sites as dicts (see below)
        _id: 98098be20fe9023d
        attr_hidden_id: default
        attr_no_delete: True
        desc: test site
        name: default
        role: readonly
        """
        if verbose:
            level = 'stat'
        else:
            level = 'self'
        r = self._session.get("{}/api/{}/sites".format(self._baseurl, level, verify=self._verify_ssl), data="json={}")
        self._current_status_code = r.status_code
        self._check_status_code(self._current_status_code)

        data = r.json()['data']

        if filters:
            data = _filter(filters, data)

        if order_by:
            data = sorted(data, key=lambda x: x[order_by] if order_by in x.keys() else x['_id'])

        return data

    def setting(self, filters: Dict[str, Union[str, Pattern]]=None, order_by: str=None) -> list:
        """"
        List device settings.

        :param filters: dict of k/v pairs; string is compiled to regex
        :param order_by: order by a key; defaults to '_id'
        :return: A list of settings as dicts (see below for example, though 
                 note that each list element is unique in terms of keys

        _id
        advanced_feature_enabled
        alert_enabled
        key
        led_enabled
        site_id
        unifi_idp_enabled

        """
        r = self._session.get("{}/api/s/{}/rest/setting".format(self._baseurl, self._site, verify=self._verify_ssl), data="json={}")
        self._current_status_code = r.status_code
        self._check_status_code(self._current_status_code)

        data = r.json()['data']

        if filters:
            data = _filter(filters, data)

        if order_by:
            data = sorted(data, key=lambda x: x[order_by] if order_by in x.keys() else x['_id'])

        return data

    def wlan_config(self, filters: Dict[str, Union[str, Pattern]]=None, order_by: str=None) -> list:
        """
        List wireless configuration.

        :param filters: dict of k/v pairs; string is compiled to regex
        :param order_by: order by a key; defaults to '_id'
        :return: A list of wlans as dicts (see below)
        _id
        enabled
        hide_ssid
        name
        security
        site_id
        uapsd_enabled
        wep_idx
        wlangroup_id
        """
        r = self._session.get("{}/api/s/{}/rest/wlanconf".format(self._baseurl, self._site, verify=self._verify_ssl), data="json={}")
        self._current_status_code = r.status_code
        self._check_status_code(self._current_status_code)

        data = r.json()['data']

        if filters:
            data = _filter(filters, data)

        if order_by:
            data = sorted(data, key=lambda x: x[order_by] if order_by in x.keys() else x['_id'])

        return data
