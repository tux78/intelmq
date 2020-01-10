# -*- coding: utf-8 -*-
"""
RSDParserBot parses McAfee ePO Rogue System Detection observations.
This bot generates one message per identified system, which can
be used in subsequent output Bots

Parameter:
rsd_isrogue: [BOOL] process rogue systems only
rsd_isactive: [BOOL] process active systems only
rsd_isnew: [BOOL] process new observations only
"""
import json

import intelmq.lib.utils as utils
# imports for additional libraries and intelmq
from intelmq.lib.bot import Bot


class RSDParserBot(Bot):

    def process(self):
        report = self.receive_message()
        raw_report = utils.base64_decode(report.get('raw'))
        rogue_systems = json.loads(raw_report)

        for system in rogue_systems:
            
            if ((self.parameters.rsd_isrogue and system['RSDDetectedSystems.Rogue'])
                and (self.parameters.rsd_isnew and system['RSDDetectedSystems.NewDetection'])
                and not (self.parameters.rsd_isactive and system['RSDDetectedSystems.Inactive'])
                and not (system['RSDDetectedSystems.Exception'])):

                # forward system information
                event = self.new_event(report)
                event.add('output', system)
                self.send_message(event)

        self.acknowledge_message()

BOT = RSDParserBot
