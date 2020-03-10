# -*- coding: utf-8 -*-
"""
SyslogParserBot parses syslog data.
syslog_regex: Regular Expression used to retrieve information
"""

import base64
import json
import re

import intelmq.lib.utils as utils

from intelmq.lib.bot import Bot

class SyslogParserBot(Bot):

    def init (self):

        self.pattern_string = self.parameters.syslog_regex
        self.fields = {}

        # Replace the '.' in any named group
        # required to follow the Harmonization Guide
        # The actual fields are stored in the self.fields dictionary
        for field in re.findall (r"\<([^\>]+)", self.pattern_string):
            key = field.replace (".", "")
            self.fields[key] = field
            self.pattern_string = self.pattern_string.replace (field, key)

        self.parser = re.compile (self.pattern_string)
        self.logger.info ("Pattern: " + self.pattern_string)

    def process (self):

        report = self.receive_message()
        raw = utils.base64_decode(report.get('raw'))

        retVal = self.parser.match (raw)
        if retVal:
            event = self.new_event (report)
            for key, value in retVal.groupdict().items():
                if self.fields[key].split(".")[0] == "extra":
                    extra_dict = event.get ("extra")
                    if not extra_dict:
                        extra_dict = {}
                    extra_dict[self.fields[key].split(".")[1]] = value
                    event.add ("extra", extra_dict)
                else:
                    event.add (self.fields[key], value)
            self.send_message (event)

        self.acknowledge_message()

BOT = SyslogParserBot
