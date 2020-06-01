# -*- coding: utf-8 -*-
"""
ESMDSParserBot parses McAfee ESM data source information.

"""
import json

import intelmq.lib.utils as utils
# imports for additional libraries and intelmq
from intelmq.lib.bot import Bot


class ESMDSParserBot(Bot):

    def process (self):

        report = self.receive_message()
        datasources = utils.base64_decode(report.get('raw'))
        datasources = json.loads(datasources)

        for datasource in datasources:
            event = self.new_event (report)
            event.add ('output', datasource)
            self.send_message (event)
        self.acknowledge_message()

BOT = ESMDSParserBot
