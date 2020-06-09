# -*- coding: utf-8 -*-
"""
GetcleanParserBot parses McAfee Getclean tool reports.

Parameter:
none
"""

import json
try:
    import xmltodict
except ImportError:
    xmltodict = None

# imports for additional libraries and intelmq
import intelmq.lib.utils as utils
from intelmq.lib.bot import Bot


class GetcleanParserBot(Bot):

    def init(self):
        if xmltodict is None:
            raise ValueError("Could not import 'xmltodict'. Please install it.")

    def process(self):
        report = self.receive_message()
        raw_report = utils.base64_decode(report.get('raw'))

        files = xmltodict.parse(raw_report)['xsl:stylesheet']['data:GetClean']['file']
        for file in files:
            event = self.new_event()
            # Add necessary attributes, e.g. for TIE
            event.add('malware.name', file['@name'])
            event.add('malware.hash.md5', file['@md5'])
            event.add('malware.hash.sha256', file['@sha256'])
            file['risk'] = file['@type']
            # Add getclean attributes
            event.add('extra', file)
            self.send_message(event)

        self.acknowledge_message()

BOT = GetcleanParserBot
