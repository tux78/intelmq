# -*- coding: utf-8 -*-
"""

MARExpertBot queries environment for occurences of IOCs via McAfee Active Response.

Parameter:
dxl_config_file: string
lookup_type: string

"""

try:
    from dxlclient.client_config import DxlClientConfig
    from dxlclient.client import DxlClient
except ImportError:
    DxlClient = None
try:
    from dxlmarclient import MarClient, ResultConstants
except ImportError:
    MarClient = None

# imports for additional libraries and intelmq
from intelmq.lib.bot import Bot
from intelmq.lib.exceptions import MissingDependencyError


class MARExpertBot(Bot):

    params = ['name', 'output', 'op', 'value']

    query = {
        'Hash':
            [
                ['Files', 'md5', 'EQUALS', 'malware.hash.md5'],
                ['Files', 'sha1', 'EQUALS', 'malware.hash.sha1'],
                ['Files', 'sha256', 'EQUALS', 'malware.hash.sha256']
            ],
        'DestSocket':
            [
                ['NetworkFlow', 'dst_ip', 'EQUALS', 'destination.ip'],
                ['NetworkFlow', 'dst_port', 'EQUALS', 'destination.port']
            ],
        'DestIP':
            [
                ['NetworkFlow', 'dst_ip', 'EQUALS', 'destination.ip']
            ],
        'DestFQDN':
            [
                ['DNSCache', 'hostname', 'EQUALS', 'destination.fqdn']
            ]
    }

    def init(self):
        if DxlClient is None:
            raise MissingDependencyError('dxlclient')
        if MarClient is None:
            raise MissingDependencyError('dxlmarclient')

        self.config = DxlClientConfig.create_dxl_config_from_file(self.parameters.dxl_config_file)

    def process(self):
        report = self.receive_message()

        mar_query = []
        for item in self.query[self.parameters.lookup_type]:
            query_dict = {key: value for key, value in zip(self.params, item)}
            try:
                query_dict['value'] = report[query_dict['value']]
                mar_query.append(query_dict)
            except KeyError:
                pass
        if mar_query:
            self.logger.info('Executing query with the following parameters: ' + str(mar_query))
            for ip_address in self.MAR_Query(mar_query):
                event = self.new_event(report)
                event.add('source.ip', ip_address)
                self.send_message(event)

        self.acknowledge_message()

    def MAR_Query(self, mar_search_str):

        # Create the client
        with DxlClient(self.config) as client:

            # Connect to the fabric
            client.connect()

            # Create the McAfee Active Response (MAR) client
            marclient = MarClient(client)
            marclient.response_timeout = 30

            # Start the search
            results_context = marclient.search(
                projections=[
                    {
                        "name": "HostInfo",
                        "outputs": ["hostname", "ip_address"]
                    }
                ],
                conditions={
                    "or": [
                        {
                            "and": mar_search_str
                        }
                    ]
                }
            )

            # Iterate the results of the search
            if results_context.has_results:
                results = results_context.get_results()
                for item in results[ResultConstants.ITEMS]:
                    yield (item['output']['HostInfo|ip_address'])

BOT = MARExpertBot
