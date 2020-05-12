# -*- coding: utf-8 -*-
"""
ESMOutputBot connects to McAfee Enterprise Security Manager, and updates IP based watchlists

Parameters:
esm_ip: IP Address of ESM
esm_user: username to connect to ESM
esm_password: Password of esm_user
esm_watchlist: Destination watchlist to update
field: field from IntelMQ message to extract (e.g. destination.ip)

"""

from intelmq.lib.bot import Bot
from intelmq.lib.exceptions import MissingDependencyError
import json

try:
    import requests
except ImportError:
    requests = None
try:
    import base64
except ImportError:
    base64 = None

class ESMIPOutputBot(Bot):

    def init(self):
        if requests is None:
            raise MissingDependencyError("requests")
        if base64 is None:
            raise MissingDependencyError("base64")

        self.esm = ESM(
            self.parameters.esm_ip,
            self.parameters.esm_user,
            self.parameters.esm_password
        )
        try:
            self.esm.login()
        except Exception:
            raise ValueError('Could not Login to ESM.')

        watchlist_filter = {'filters': [{'name': 'IPAddress', 'id': 0}]}
        self.watchlist_id = None
        try:
            retVal = self.esm.post('sysGetWatchlists?hidden=false&dynamic=false&writeOnly=false&indexedOnly=false',
                                   watchlist_filter)
            for WL in retVal.json():
                if (WL['name'] == self.parameters.esm_watchlist):
                    self.watchlist_id = WL['id']
        except TypeError:
            self.logger.error('Watchlist not found. Please verify name of the watchlist.')
            self.stop()

    def process(self):
        event = self.receive_message()
        try:
            payload = {
                'watchlist': self.watchlist_id,
                'values': '["' + event.get(self.parameters.field) + '"]'
            }
            retval = self.esm.sysAddWatchlistValues(payload)
            self.logger.info('ESM Watchlist updated: ' + event.get(self.parameters.field))
        except Exception:
            self.logger.exception('Error when updating watchlist.')
        self.acknowledge_message()

class ESM ():

    headers = {}

    def __init__ (self, esm_ip, esm_user, esm_pw):
        self.url = "https://{}/rs/esm/v2/".format(esm_ip)
        self.user = base64.b64encode(esm_user.encode('utf-8')).decode()
        self.pw = base64.b64encode(esm_pw.encode('utf-8')).decode()

        self.headers = {
            'content-type': 'application/json'
        }

    def login (self):

        payload = {
            'username': self.user,
            'password': self.pw,
            'locale': 'en_US',
            'os': 'Win32'
        }
        response = self.post ('login', payload)
        self.headers['X-Xsrf-Token'] = response.headers['Xsrf-Token']
        self.headers['Cookie'] = response.headers['Set-Cookie']

    def logout (self):
        response = self.post ('logout', '')
        del self.headers['X-Xsrf-Token']
        del self.headers['Cookie']

    def sysAddWatchlistValues (self, payload):

        response = self.post ('sysAddWatchlistValues', payload)
        return payload

    def post (self, method, payload):

        if 'X-Xsrf-Token' not in self.headers and method != 'login':
            print (self.headers)
            raise ValueError('You have to login first.')

        response = requests.post(
            self.url + method,
            headers = self.headers,
            data = json.dumps (payload),
            verify = False
        )
        return response

BOT = ESMIPOutputBot
