# -*- coding: utf-8 -*-

"""
MISPParserFileobjectBot parses file object information (hashes, filename)
out of a MISP event
"""

import json
from datetime import datetime
from urllib.parse import urljoin

from intelmq.lib import utils
from intelmq.lib.bot import Bot


class MISPParserFileobjectBot(Bot):

    # Event categories we process
    SUPPORTED_MISP_CATEGORIES = [
        'Payload delivery',
        'Artifacts dropped',
        'Payload installation',
    ]

    # MISP to IntelMQ data type mapping
    MISP_TYPE_MAPPING = {
        'md5': 'malware.hash.md5',
        'sha1': 'malware.hash.sha1',
        'sha256': 'malware.hash.sha256',
        'filename': 'malware.name'
    }

    def init(self):
        self.logger.info('MISP Parser Started.')

    def process(self):
        report = self.receive_message()
        raw_report = utils.base64_decode(report.get('raw'))
        misp_event = json.loads(raw_report)

        # iterate through MISP Objects of Type FILE
        for obj in misp_event['Object']:

            if (obj['meta-category'] == 'file'):

                # Create intelMQ event
                event = self.new_event(report)
                event.add('raw', json.dumps(obj, sort_keys=True))
                event.add('misp.event_uuid', misp_event['uuid'])

                for attribute in obj['Attribute']:
                    # get details of attribute
                    value = attribute['value']
                    type_ = attribute['type']
                    category = attribute['category']

                    if (category in self.SUPPORTED_MISP_CATEGORIES and
                        type_ in self.MISP_TYPE_MAPPING):

                        # Add attribute to intelMQ event
                        event.add(self.MISP_TYPE_MAPPING[type_], value)

                # Send intelMQ event
                self.send_message(event)

        self.acknowledge_message()


BOT = MISPParserFileobjectBot

