# -*- coding: utf-8 -*-
"""
ESMOutputBot connects to McAfee Enterprise Security Manager, and boards a datasource

Parameters:
esm_ip: IP Address of ESM
esm_user: username to connect to ESM
esm_password: Password of esm_user

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



class ESMDSOutputBot(Bot):

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
            self.esm.logout()
        except Exception:
            raise ValueError('Could not Login to ESM.')


    def process(self):
        event = self.receive_message()
        datasources = event.get ('output')
        self.logger.info('Message received.')
        try:
            self.esm.login ()
            self.esm.dsAddDataSources (datasources)
            self.logger.info('ESM data sources added.')
            self.acknowledge_message()
        except Exception:
            self.logger.exception('Error when adding data sources.')
        self.acknowledge_message()

class ESM ():

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
        response = self._esm_sendquery ('login', payload)
        self.headers['X-Xsrf-Token'] = response.headers['Xsrf-Token']
        self.headers['Cookie'] = response.headers['Set-Cookie']

    def logout (self):
        response = self._esm_sendquery ('logout', '')

    def dsAddDataSources (self, datasource):

        for erc, ds in datasource.items():
            payload = {
                'receiverId': erc,
                'datasources': ds
            }
            response = self._esm_sendquery ('dsAddDataSources', payload)
        return True

    def _esm_sendquery (self, method, payload):

        if 'X-Xsrf-Token' not in self.headers and method != 'login':
            raise ValueError('You have to login first.')

        response = requests.post(
            self.url + method,
            headers = self.headers,
            data = json.dumps (payload),
            verify = False
        )

        return response

BOT = ESMDSOutputBot
