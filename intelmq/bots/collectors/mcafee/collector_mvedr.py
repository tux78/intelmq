"""
McAfee MVISION EDR Collector Bot
Connects to a McAfee MVISION API and processes streamed events

Parameters:
mvedr_url: MVISION EDR Host to connect to
mvedr_topic: MVISION Topic to connect to
mvedr_username: Username
mvedr_password: Password
"""

import time
import threading
import json, requests

from intelmq.lib.bot import CollectorBot
from dxlstreamingclient.channel import Channel, ChannelAuth, ConsumerError

class mvedrCollectorBot(CollectorBot):

    def init(self):
        self._auth=ChannelAuth(self.parameters.mvedr_url,
                    self.parameters.mvedr_username,
                    self.parameters.mvedr_password,
                    verify_cert_bundle='')

    def process(self):
        self.logger.info("Starting process.")
        try:
            with Channel(
                self.parameters.mvedr_url,
                auth=self._auth,
                consumer_group='mvisionedr_events_intelmq',
                verify_cert_bundle='') as channel:

                def process_callback(payloads):
                    if not payloads == []:
                        for payload in payloads:
                            self.logger.info('Payload: {0}'.format(json.dumps(payload)))

                            event = self.new_report()
                            event.add("raw", json.dumps(payload))
                            self.send_message(event)

                    return True

                self.logger.info("Starting event loop.")
                channel.run(process_callback, wait_between_queries=30, topics=['threatEvents'])

        except Exception as e:
            self.logger.info("Error occured." + str(e))

    def shutdown(self):
        self.logger.info("Shutting down.")

BOT = mvedrCollectorBot
