"""
McAfee DSB Collector Bot
Connects to a McAfee Data Streaming Bus via KAFKA and processes streamed events

Parameters:
dsb_ip: IP address of DSB
dsb_client_cert: Client certificate (key/public)
dsb_ca: CA certificate
dsb_topic: name of the topic to subscribe
"""

import time
import json, requests

from intelmq.lib.bot import CollectorBot
from kafka import KafkaConsumer

class dsbCollectorBot(CollectorBot):

    def init(self):

        self.dsb_consumer = KafkaConsumer (
            group_id = "intelMQ",
            security_protocol = "SSL",
            ssl_cafile = self.parameters.dsb_ca,
            ssl_certfile = self.parameters.dsb_client_cert,
            ssl_keyfile = self.parameters.dsb_client_cert,
            ssl_check_hostname = False,
            bootstrap_servers = self.parameters.dsb_ip)

        self.dsb_consumer.subscribe(pattern=self.parameters.dsb_topic)

    def process(self):

        self.logger.info("Processing topic: " + str(self.dsb_consumer.subscription()))
        try:

            for message in self.dsb_consumer:

                event = self.new_report()
                event.add("raw", message.value)

                self.send_message(event)

        except Exception as err:
            self.logger.error('Error during message processing: ' + str(err))


    def shutdown(self):
        self.logger.info("Shutting down.")
        # self.dsb_consumer.unsubscribe()
        # self.dsb_consumer.close()

BOT = dsbCollectorBot
