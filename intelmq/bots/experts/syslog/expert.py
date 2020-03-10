# -*- coding: utf-8 -*-
"""

SyslogExpertBot translates field content.

Parameter:
field_dict: string (JSON dict)

Example:
{
  "extra.field_to_observe": {
    "orig_value_1" : "new_value_1",
    "orig_value_2" : "new_value_2"
  }
}

"""

# imports for additional libraries and intelmq
import json

from intelmq.lib.bot import Bot
from intelmq.lib.exceptions import MissingDependencyError


class SyslogExpertBot(Bot):

    def init(self):
        self.field_dict = self.parameters.field_dict
        # self.field_dict = json.loads (self.parameters.field_dict)

    def process(self):
        report = self.receive_message()

        for field in self.field_dict:
            if (report.get(field) in self.field_dict[field]):
                report.change(field, self.field_dict[field][report.get(field)])
        event = self.new_event(report)
        self.send_message(event)

        self.acknowledge_message()

BOT = SyslogExpertBot
