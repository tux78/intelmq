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
            event.add ('source.ip', datasource['ipAddress'])
            payload = {'details': datasource, 'id': datasource['id'], 'type': 'parent'}
            event.add ('extra', payload)
            for parameter in datasource['parameters']:
                if parameter['key'] == 'hostname':
                    try:
                        event.add ('source.fqdn', parameter['value'])
                    except:
                        pass
                    break
            self.send_message (event)

        self.acknowledge_message()

BOT = ESMDSParserBot
