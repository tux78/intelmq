# -*- coding: utf-8 -*-
"""
ESMParserBot parses McAfee ESM data source export files.

"""
import json

import intelmq.lib.utils as utils
# imports for additional libraries and intelmq
from intelmq.lib.bot import Bot


class ESMParserBot(Bot):

    ESM_FIELD_RENAME = {
        'dsname': 'name',
        'ip': 'ipAddress',
        'parsing': 'enabled',
        'rec_id' : 'receiverId'
    }

    ESM_BOOL = {
        'yes': True,
        'no': False
    }

    def process (self):

        report = self.receive_message()
        raw = utils.base64_decode(report.get('raw')).splitlines()

        # Dismiss first line (versioning information)
        raw.pop(0)
        headers = raw.pop(0).split(',')

        for line in raw:
            values = line.split(',')
            datasource = {}
            for header in headers:
                value = values.pop(0).strip('\"')
                # Normalize BOOLs
                if value in self.ESM_BOOL:
                    value = self.ESM_BOOL[value]
                # Rename ESM Field Names
                # Covers inconsistence between export file and ESM API
                if header in self.ESM_FIELD_RENAME:
                    header = self.ESM_FIELD_RENAME[header]
                datasource[header] = value
            # Send Event, one per line/data source
            if datasource['op'] == 'add':
                event = self.new_event (report)
                event.add ('output', datasource)
                self.send_message (event)

                self.logger.info (str (datasource))

        self.acknowledge_message()

BOT = ESMParserBot
