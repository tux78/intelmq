# -*- coding: utf-8 -*-
"""

ESMDSDNSExpertBot looks up the hostname in DNS from data source details

Parameter:
dns_server: DNS Server IP to query

"""

# import required libraries
import json
import dns
from dns.resolver import NoNameservers, NXDOMAIN

# imports for additional libraries and intelmq
from intelmq.lib.bot import Bot
from intelmq.lib.exceptions import MissingDependencyError


class ESMDSDNSExpertBot(Bot):

    def init(self):
        self.dns_server = self.parameters.dns_server
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.nameservers.append(self.parameters.dns_server)

    def process(self):
        report = self.receive_message()
        datasource = json.loads(report.get('output'))

        hostname = ''
        for parameter in datasource['parameters']:
            if parameter['key'] == 'hostname':
                hostname = parameter['value']
                break

        if hostname != '':
            try:
                response = self.resolver.query(hostname, 'A')
            except (NoNameservers, NXDOMAIN):
                event = self.new_event(report)
                event.add ('source.local_hostname', hostname)
                self.send_message(event)

        self.acknowledge_message()

BOT = ESMDSDNSExpertBot
