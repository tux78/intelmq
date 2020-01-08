"""
MWG Output Bot
Connects to a McAfee Web Gateway and updates a particular list

Parameters:
mwg_ip: IP address of MWG
mwg_user: username to connect to MWG
mwg_password: password of mwg_user
mwg_list: name of the list to connect
"""

import time
import json, requests
import xml.etree.ElementTree as xml

from intelmq.lib.bot import Bot
from intelmq.lib.utils import base64_decode

class mwgOutputBot(Bot):

    MWG_LIST_MAPPING = {
        'com.scur.type.ip': 'source.ip',
        'com.scur.type.string': 'source.fqdn',
        'com.scur.type.regex': 'source.fqdn'
    }

    def init(self):
        self.mwg_client = mwg(self.parameters.mwg_ip, 
                              self.parameters.mwg_user, 
                              self.parameters.mwg_password,
                              self.parameters.mwg_list)

    def process(self):
        report = self.receive_message()

        raw_report = report.get(self.MWG_LIST_MAPPING[self.mwg_client.listType])
        try:
            self.mwg_client.insert_list_entry(raw_report)
        except KeyError:
            self.logger.debug('Duplicate Entry: ' + raw_report)
            self.acknowledge_message()
            pass

    def shutdown(self):
        self.mwg_client.logout()

class mwg():

    def __init__(self, mwg_ip, mwg_user, mwg_password, mwg_list):
        # some variables
        self.headers = {'Content-Type': 'application/xml'}
        _auth = {'userName': mwg_user,
                 'pass': mwg_password
                }
        self.url = 'https://' + mwg_ip + ':4712/Konfigurator/REST/'

        response = requests.post(self.url + "login", self.headers, params = _auth, verify = False)

        if response.status_code == 200:
            self.authCookie = {'JSESSIONID': response.cookies['JSESSIONID']}
        else:
            raise ValueError('Could not connect to MWG. The error message provided is [{}: {}]'.format(response.status_code, response.content.decode()))

        self._get_list_id(mwg_list)

    def _get_list_id(self, listName):
        _params = {'name': listName}
        response = requests.get(self.url + "list", headers = self.headers, cookies = self.authCookie, params = _params, verify = False)

        self.listID = xml.fromstring(response.content).find('entry/id').text

        if response.status_code != 200 or self.listID == None:
            raise ValueError ('The intended list [{}] could not be found.'.format(listName + response.status_code))

        self.listType = self.listID[0:self.listID.rfind('.')]

    def get_list_content(self):

        response = requests.get(self.url + 'list/' + self.listID, headers = self.headers, cookies = self.authCookie, verify = False)
        if response.status_code != 200:
            raise ValueError('Could read list entries. The following error message was provided: [{}: {}]'.format(response.status_code, response.content.decode()))

        return response.content.decode()

    def insert_list_entry(self, value):

        listEntry = '''
                <entry xmlns="http://www.w3org/2011/Atom">
                    <content type="application/xml">
                        <listEntry>
                            <entry>{}</entry>
                            <description></description>
                        </listEntry>
                    </content>
                </entry>
                '''
        listEntry = listEntry.format(value)

        response = requests.post(self.url + 'list/' + self.listID + '/entry/0/insert',
                                 headers = self.headers, cookies = self.authCookie, data = listEntry, verify = False)
        if response.status_code != 200:
            raise KeyError('Could not create entry. The following error message was provided: [{}: {}]'.format(response.status_code, response.content.decode()))
        else:
            self.commit()

    def commit(self):
        response = requests.post(self.url + 'commit', headers = self.headers, cookies = self.authCookie, verify = False)
        if response.status_code != 200:
            raise ValueError('Could not commit changes. The following error message was provided: [{}: {}]'.format(response.status_code, response.content.decode()))

    def logout(self):
        response = requests.post(self.url + 'logout', headers = self.headers, cookies = self.authCookie, verify = False)
        if response.status_code != 200:
            raise ValueError('Could not logout. The following error message was provided: [{}: {}]'.format(response.status_code, response.content.decode()))


BOT = mwgOutputBot
