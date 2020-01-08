# -*- coding: utf-8 -*-
"""
MWGParserBot parses McAfee Web Gateway list reports.
This bot generates one message per identified list entry, depending on the list type
- IP Lists -> source.ip
- URL lists -> source.fqdn

"""
import json
import xml.etree.ElementTree as xml

# imports for additional libraries and intelmq
from intelmq.lib.bot import Bot
import intelmq.lib.utils as utils


class MWGParserBot(Bot):

    ATD_TYPE_MAPPING = {
        'domain': 'source.fqdn',
        'hostname': 'source.fqdn',
        'Name': 'malware.name',
        'Md5': 'malware.hash.md5',
        'Sha1': 'malware.hash.sha1',
        'Sha256': 'malware.hash.sha256',
        'Ipv4': 'destination.ip',
        'Port': 'destination.port',
        'Url': 'destination.fqdn',
    }

    def process(self):
        report = self.receive_message()
        raw_report = utils.base64_decode(report.get('raw'))

        listType = xml.fromstring(raw_report).find('type').text
        listContent = xml.fromstring(raw_report).findall('content/list/content/listEntry/entry')

        if listType == 'com.scur.type.ip':
            for entry in listContent:
                event = self.new_event(report)
                event.add('source.ip', entry.text)
                self.send_message(event)

        if listType == 'com.scur.type.string' or listType == 'com.scur.type.regex':
            for entry in listContent:
                event = self.new_event(report)
                event.add('source.fqdn', entry.text)
                self.send_message(event)

        self.acknowledge_message()


BOT = MWGParserBot
