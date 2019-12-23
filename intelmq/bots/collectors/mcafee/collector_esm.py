# -*- coding: utf-8 -*-
"""
ESMCollectorBot connects to McAfee Enterprise Security Manager, and downloads correlated events

Parameters:
esm_ip: IP Address of ESM
esm_user: username to connect to ESM
esm_password: Password of esm_user
sigID: Signature ID to filter on
fields: comma-separated list of fields

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

class ESMCollectorBot(CollectorBot):

    def init(self):
        if requests is None:
            raise ValueError("Could not import 'requests'. Please install it.")

        # Log in to ESM
        enc_user = base64.b64encode (self.parameters.esm_user.encode('utf-8')).decode()
        enc_password = base64.b64encode (self.parameters.esm_password.encode('utf-8')).decode()

        headers = {'Content-Type': 'application/json'}
        data = {
            'username' : enc_user,
            'password' : enc_password,
            'locale' : 'en_US',
            'os' : 'Win32'
        }

        self.url = 'https://' + self.parameters.esm_ip + '/rs/esm/'
        try:
            response = requests.post(
                self.url + 'login',
                data = json.dumps (data),
                headers = headers,
                verify = False
            )
        except requests.exceptions.ConnectionError:
            raise ValueError('Error connecting to ESM.')

        if response.status_code in [400, 401]:
            raise ValueError('Invalid username or password.')
        elif 402 <= response.status_code <= 600:
            raise ValueError('ESM login error: ' + response.text)

        # Store XSRF Token for subsequent use

        self.auth_header = {'Content-Type': 'application/json'}
        self.auth_header['Cookie'] = response.headers.get('Set-Cookie')
        self.auth_header['X-Xsrf-Token'] = response.headers.get('Xsrf-Token')
        self.auth_header['SID'] = response.headers.get('Location')

        # additional parameters
        self.sigID = self.parameters.sigID
        self.lastTimeCollected = datetime.now(timezone.utc).isoformat()
        self.field_list = []
        self.filter_list = []

        fields = self.parameters.fields.split(',')
        filters = {'field': 'DSIDSigID', 'operator': 'IN', 'values': self.sigID}

        # Prepend additional requried fields
        self.field_list.append({'name': 'DSID'})
        self.field_list.append({'name': 'IPSID'})
        self.field_list.append({'name': 'AlertID'})

        # Append fields selected by user
        for field in fields:
            self.field_list.append({'name': field})

        self.filter_list.append ({
            'type': 'EsmFieldFilter',
            'field': {'name': filters['field']},
            'operator': filters['operator'],
            'values': [{
                'type': 'EsmBasicValue',
                'value': filters['values']
            }]
        })

        self.order = [{
            'direction': 'DESCENDING',
            'field': {'name': 'LastTime'}
        }]

    def process(self):
        # Prepare payload for initiating the query
        currentTime = datetime.now(timezone.utc).isoformat()
        payload = {'config' :
            {
            # 'timeRange' : 'CURRENT_DAY',
            'timeRange' : 'CUSTOM',
            'customStart' : str(self.lastTimeCollected),
            'customEnd' : str(currentTime),
            'order' : self.order,
            'includeTotal' : False,
            'fields' : self.field_list,
            'filters' : self.filter_list,
            'limit' : 0
            }
        }
        self.lastTimeCollected = currentTime

        # Initiate query on ESM
        response = requests.post (
            self.url + 'qryExecuteDetail?type=EVENT&reverse=false',
            data = json.dumps (payload),
            headers = self.auth_header,
            verify = False
        )
        resultID = response.json()['return']['resultID']['value']

        # Wait until query is finished on ESM
        payload = {'resultID' : {'value' : resultID}}
        status = False
        while not status:
            response = requests.post (
                self.url + 'qryGetStatus',
                data = json.dumps (payload),
                headers = self.auth_header,
                verify = False
            )
            status = response.json()['return']['complete']

        # Retrieve content from ESM
        response = requests.post (
            self.url + 'qryGetResults/?startPos=0&numRows=10&reverse=false',
            data = json.dumps (payload),
            headers = self.auth_header,
            verify = False
        )

        # Evaluate events, create message per event
        for row in response.json()['return']['rows']:
            self._evaluate_event (row)

        # Sleep for some time before querying again
        time.sleep(60)

    def _evaluate_event (self, event):
        # For correlated events, the IOCs have to be collected
        if event['values'][0] == '47':
            # Correlated event, get indicators
            payload = {
                'eventId': {'value' : event['values'][1] + '|' + event['values'][2]},
                'fields' : self.field_list
            }

            # Initiate query
            response = requests.post (
                self.url + 'qryGetCorrEventDataForID?queryType=EVENT',
                data = json.dumps (payload),
                headers = self.auth_header,
                verify = False
            )

            # Add IOCs to event
            event['ioc'] = []
            for row in response.json()['return']:
                event['ioc'].append(row)

        # Create and send message
        event_report = self.new_report()
        event_report.add('raw', json.dumps(event))
        self.send_message (event_report)

BOT = ESMCollectorBot
