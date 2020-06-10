# -*- coding: utf-8 -*-
"""

ESMDSFilterExpertBot looks up the hostname in DNS from data source details

Parameter:
datasource_id: Array of data source IDs

"""

# import required libraries
import json

# imports for additional libraries and intelmq
from intelmq.lib.bot import Bot
from intelmq.lib.exceptions import MissingDependencyError


class ESMDSFilterExpertBot(Bot):

    def init(self):
        self.datasource_id = self.parameters.datasource_id

    def process(self):
        report = self.receive_message()

        print(report['extra.id'] + ': ' + str(self.datasource_id))
        if (self.datasource_id == [] or report['extra.id'] in self.datasource_id):
            event = self.new_event(report)
            self.send_message(event)

        self.acknowledge_message()

BOT = ESMDSFilterExpertBot
