"""
openDXL ePO Commands Bot
Connects to a openDXL fabric and executes ePO DXL Command

Parameters:
dxl_config_file: string
dxl_epo_command: string
dxl_epo_parameter: string
"""

import time
import json

from intelmq.lib.bot import CollectorBot
from intelmq.lib.exceptions import MissingDependencyError

try:
    from dxlclient.client_config import DxlClientConfig
    from dxlclient.client import DxlClient
    from dxlepoclient import EpoClient
except ImportError:
    DxlClient = None


class ePODXLCommandCollectorBot(CollectorBot):

    def init(self):
        if DxlClient is None:
            raise MissingDependencyError("dxlclient")

        self.EPO_UNIQUE_ID = None
        self.EPO_COMMAND = self.parameters.dxl_epo_command
        self.EPO_PARAMETER = self.parameters.dxl_epo_parameter

        self.config = DxlClientConfig.create_dxl_config_from_file(
            self.parameters.dxl_config_file
        )

    def process(self):

        with DxlClient(self.config) as client:

            # Connect to the fabric
            try:
                client.connect()
                if client.connected:
                    self.logger.info('DXL Client connected')
            except Exception:
                self.logger.error('Error during client connect.')
                raise

            # Initiating ePO Command
            epo_client = EpoClient (client, self.EPO_UNIQUE_ID)
            response = epo_client.run_command (self.EPO_COMMAND, self.EPO_PARAMETER)
            self.logger.debug ('DXL Response: ' + str(response))

            # Create and send message
            event = self.new_report()
            event.add ('raw', response)
            self.send_message (event)

BOT = ePODXLCommandCollectorBot
