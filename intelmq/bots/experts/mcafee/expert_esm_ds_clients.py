# -*- coding: utf-8 -*-
"""

ESMDSDNSExpertBot looks up the hostname in DNS from data source details

Parameter:
esm_ip: IP Address of ESM
esm_user: username to connect to ESM
esm_password: Password of esm_user

"""

# import required libraries
import json
import base64
try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    requests = None

# imports for additional libraries and intelmq
from intelmq.lib.bot import Bot
from intelmq.lib.exceptions import MissingDependencyError


class ESMDSClientsExpertBot(Bot):

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

    def process(self):
        report = self.receive_message()

        if not(self._heartbeat()):
            raise ValueError('Cannot login.')

        payload = {'datasourceId' : report['extra.id']}
        if (report['extra.details']['childCount'] > 0 and report['extra.details']['childType'] == 2):
            retVal = self._call_API('dsGetDataSourceClients', payload).json()
            for client in retVal:
                event = self.new_event ()
                event.add ('source.fqdn', client['host'])
                event.add ('source.ip', client['ipAddress'])
                payload = {'details': client, 'id': client['id'], 'type': 'client'}
                event.add ('extra', payload)
                self.send_message (event)

        self.acknowledge_message()

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

BOT = ESMDSClientsExpertBot
