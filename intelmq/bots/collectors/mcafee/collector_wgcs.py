"""
McAfee Web Gateway Cloud Service Collector Bot
Connects to a McAfee WGCS, downloads events stored in a file, 
and generates a message once done

Parameters:
wgcs_location: WGCS Log Location (US vs EU)
wgcs_customer: WGCS Customer ID
wgcs_username: Username
wgcs_password: Password
wgcs_path: location to store downloaded events
"""

import time
import json, requests

from intelmq.lib.bot import CollectorBot

class wgcsCollectorBot(CollectorBot):

    def init(self):
        # WGCS API Version
        self._api_version="5"
        # Max timespan for a single file
        self._max_span=300
        if (self.parameters.wgcs_location == "EU"):
            self._wgcs_url = "https://eu.msg.mcafeesaas.com"
        else:
            self._wgcs_url = "https://msg.mcafeesaas.com"
        self._step=self.parameters.rate_limit
        self._headers={
            'Accept': 'text/csv',
            'X-MWG-API-Version': self._api_version
        }

    def download_logs(self, timeFrom, timeTo):
        url=self._wgcs_url+':443/mwg/api/reporting/forensic/' \
            +str(self.parameters.wgcs_customer) \
            +'?filter.requestTimestampFrom='+str(timeFrom) \
            +'&filter.requestTimestampTo='+str(timeTo) \
            +'&order.0.requestTimestamp=asc'
        filename=self.parameters.wgcs_path+'WGCSLog_'+str(timeTo)+'.csv'

        with requests.Session() as session:
            session.headers.update(self._headers)
            response=session.get(url, auth=(self.parameters.wgcs_username, self.parameters.wgcs_password))
            file=open(filename, 'wb')
            file.write(response.content)
            file.close()

        event = self.new_report()
        event.add("raw", 'Logs downloaded. Filename: '+filename+' from '+str(timeFrom)+' to '+str(timeTo))
        self.send_message(event)

    def process(self):
        # Get current time in EPOCH (seconds)
        timeTo=int(time.time())
        # round down by rate limit, and take the previous one
        timeTo=timeTo-(timeTo%self._step)-self._step
        timeFrom=timeTo-self._step+1

        self.download_logs(timeFrom, timeTo)


BOT = wgcsCollectorBot
