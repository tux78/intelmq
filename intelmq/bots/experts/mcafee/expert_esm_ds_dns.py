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

        try:
            event = self.new_event(report)
            response = self.resolver.query(report['source.fqdn'], 'A')
        except (NoNameservers, NXDOMAIN):
            event.add ('source.local_hostname', report['source.fqdn'])
            event.add ('status', 'DNS Lookup failed')
            self.send_message(event)
        except KeyError:
            event.add ('status', 'No hostname given')
            self.send_message(event)

        self.acknowledge_message()

BOT = ESMDSDNSExpertBot
