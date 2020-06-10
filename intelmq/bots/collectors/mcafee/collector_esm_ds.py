# -*- coding: utf-8 -*-
"""
ESMCollectorBot connects to McAfee Enterprise Security Manager, and downloads a list of data sources

Parameters:
esm_ip: IP Address of ESM
esm_user: username to connect to ESM
esm_password: Password of esm_user
hide_disabled: omit disabled data sources
get_details: retrieves detailed information on data sources
"""

import base64
import json
import time

from datetime import datetime, timezone
from intelmq.lib.bot import CollectorBot

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    requests = None

class ESMDataSourceCollectorBot(CollectorBot):

    def init(self):
        if requests is None:
            raise ValueError("Could not import 'requests'. Please install it.")

        # Login parameters
        self.enc_user = base64.b64encode (self.parameters.esm_user.encode('utf-8')).decode()
        self.enc_password = base64.b64encode (self.parameters.esm_password.encode('utf-8')).decode()
        self.url = 'https://' + self.parameters.esm_ip + '/rs/esm/v2/'
        self.auth_header = {'Content-Type': 'application/json'}

        # Test Login
        if not(self._heartbeat()):
            raise ValueError('Cannot login.')

        # additional parameters
        self.hide_disabled = self.parameters.hide_disabled
        self.get_details = self.parameters.get_details
        self.device_id = []
        if (self.parameters.device_id != ''):
            # Get device list from non-empty parameter
            for erc in self.parameters.device_id:
                self.device_id.append(erc)
        else:
            # Get all devices from ESM
            payload = {'types' : ['RECEIVER'] }
            response = self._call_API('devGetDeviceList?filterByRights=false', payload)
            for erc in response.json():
                self.device_id.append(erc['id'])
        self.logger.info('Handling the following device IDs: ' + str(self.device_id))

    def process(self):

        if not(self._heartbeat()):
            raise ValueError('Cannot login.')

        for erc in self.device_id:
            dslist = []
            payload = {'receiverId' : erc}
            retVal = self._call_API('dsGetDataSourceList', payload)     

            if (self.parameters.get_details):
                for ds in retVal.json():
                    payload = {'datasourceId' : str(ds['id'])}
                    parent = self._call_API('dsGetDataSourceDetail', payload).json()
                    parent['id'] = str(ds['id'])
                    dslist.append (parent)
            else:
                dslist = retVal.json()

            # Create and send message
            event_report = self.new_report()
            event_report.add('raw', json.dumps(dslist))
            self.send_message (event_report)
            self.logger.debug('Message sent.')

    def _login (self):
        self.auth_header = {'Content-Type': 'application/json'}
        data = {
            'username' : self.enc_user,
            'password' : self.enc_password,
            'locale' : 'en_US',
            'os' : 'Win32'
        }

        try:
            response = requests.post(
                self.url + 'login',
                data = json.dumps (data),
                headers = self.auth_header,
                verify = False
            )
        except requests.exceptions.ConnectionError:
            raise ValueError('Error connecting to ESM.')

        if response.status_code in [400, 401]:
            raise ValueError('Invalid username or password.')
            return False
        elif 402 <= response.status_code <= 600:
            raise ValueError('ESM login error: ' + response.text)
            return False

        # Store XSRF Token for subsequent use
        self.auth_header['Cookie'] = response.headers.get('Set-Cookie')
        self.auth_header['X-Xsrf-Token'] = response.headers.get('Xsrf-Token')
        self.auth_header['SID'] = response.headers.get('Location')

        self.logger.debug('Login successful.')
        return True

    def _heartbeat (self):

        response = requests.post(
            self.url + 'miscKeepAlive',
            headers = self.auth_header,
            verify = False
        )
        if response.status_code in [200, 204]:
            return True
        else:
            self.logger.debug('Heartbeat failed with ' + str(response.status_code) + '. Trying login.')
            return self._login()

    def _call_API (self, method, payload):

        response = requests.post (
            self.url + method,
            data = json.dumps (payload),
            headers = self.auth_header,
            verify = False
        )
        return response

BOT = ESMDataSourceCollectorBot
