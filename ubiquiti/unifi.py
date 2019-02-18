from requests import Session
import json
import re
from typing import Pattern, Dict, Union


class LoggedInException(Exception):

    def __init__(self, *args, **kwargs):
        super(LoggedInException, self).__init__(*args, **kwargs)


class API(object):
    """
    Unifi API for the Unifi Controller.

    """
    _login_data = {}
    _current_status_code = None

    def __init__(self, username: str="ubnt", password: str="ubnt", site: str="default", baseurl: str="https://unifi:8443", verify_ssl: bool=True):
        """
        Initiates tha api with default settings if none other are set.

        :param username: cloudkey username
        :param password: cloudkey password
        :param site: name of site (https://unifi:8443/manage/site/$THIS)
        :param baseurl: controller URL
        :param verify_ssl: Boolean to check the certificate validity (warns on False)
        """
        self._login_data['username'] = username
        self._login_data['password'] = password
        self._site = site
        self._verify_ssl = verify_ssl
        self._baseurl = baseurl
        self._session = Session()

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

    def login(self):
        """
        Log the user in.

        :return: None
        """
        self._current_status_code = self._session.post("{}/api/login".format(self._baseurl), data=json.dumps(self._login_data), verify=self._verify_ssl).status_code
        if self._current_status_code == 400:
            raise LoggedInException("Failed to log in to api with provided credentials")

    def logout(self):
        """
        Log the user out.

        :return: None
        """
        self._session.get("{}/logout".format(self._baseurl))
        self._session.close()

    def list_clients(self, filters: Dict[str, Union[str, Pattern]]=None, order_by: str=None) -> list:
        """
        List all available clients from the api.

        :param filters: dict of k/v pairs; string is compiled to regex
        :param order_by: order by a key; defaults to '_id'
        :return: A list of clients on the format of a dict
        """

        r = self._session.get("{}/api/s/{}/stat/sta".format(self._baseurl, self._site, verify=self._verify_ssl), data="json={}")
        self._current_status_code = r.status_code

        if self._current_status_code == 401:
            raise LoggedInException("Invalid login, or login has expired")

        data = r.json()['data']

        if filters:
            for term, value in filters.items():
                value_re = value if isinstance(value, Pattern) else re.compile(value)

                data = [x for x in data if term in x.keys() and re.fullmatch(value_re, x[term])]

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
        if self._current_status_code == 401:
            raise LoggedInException("Invalid login, or login has expired")

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
        if self._current_status_code == 401:
            raise LoggedInException("Invalid login, or login has expired")

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

        if self._current_status_code == 401:
            raise LoggedInException("Invalid login, or login has expired")

        data = r.json()['data']

        if filters:
            for term, value in filters.items():
                value_re = value if isinstance(value, Pattern) else re.compile(value)

                data = [x for x in data if term in x.keys() and re.fullmatch(value_re, x[term])]

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

        if self._current_status_code == 401:
            raise LoggedInException("Invalid login, or login has expired")

        data = r.json()['data']

        if filters:
            for term, value in filters.items():
                value_re = value if isinstance(value, Pattern) else re.compile(value)

                data = [x for x in data if term in x.keys() and re.fullmatch(value_re, x[term])]

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

        if self._current_status_code == 401:
            raise LoggedInException("Invalid login, or login has expired")

        data = r.json()['data']

        if filters:
            for term, value in filters.items():
                value_re = value if isinstance(value, Pattern) else re.compile(value)

                data = [x for x in data if term in x.keys() and re.fullmatch(value_re, x[term])]

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

        if self._current_status_code == 401:
            raise LoggedInException("Invalid login, or login has expired")

        data = r.json()['data']

        if filters:
            for term, value in filters.items():
                value_re = value if isinstance(value, Pattern) else re.compile(value)

                data = [x for x in data if term in x.keys() and re.fullmatch(value_re, x[term])]

        if order_by:
            data = sorted(data, key=lambda x: x[order_by] if order_by in x.keys() else x['_id'])

        return data
