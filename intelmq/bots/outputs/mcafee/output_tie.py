# -*- coding: utf-8 -*-
"""
TIEOutputBot connects to McAfee TIE and creates an enterprise override for a particular hash value

Parameters:
dxl_config_file: string
comment: string

"""

from intelmq.lib.bot import Bot
import json
import base64

try:
    from dxlclient.client import DxlClient
    from dxlclient.client_config import DxlClientConfig
    from dxltieclient import TieClient
    from dxltieclient.constants import HashType, TrustLevel
except ImportError:
    DxlClient = None

class TIEOutputBot(Bot):

    def init(self):
        if DxlClient is None:
            raise ValueError("Could not import 'dxlclient'. Please install it.")

        self.config = DxlClientConfig.create_dxl_config_from_file(self.parameters.dxl_config_file)
        self.dxlclient = DxlClient(self.config)

    def process(self):
        event = self.receive_message()

        payload = json.dumps(event)

        self.dxlclient.connect()
        tie_client = TieClient(self.dxlclient)

        tie_client.set_file_reputation(
            TrustLevel.MOST_LIKELY_MALICIOUS, {
                HashType.SHA256: event.get("malware.hash.sha256"),
                HashType.SHA1: event.get("malware.hash.sha1"),
                HashType.MD5: event.get("malware.hash.md5")
            },
            filename = event.get("malware.name"),
            comment = self.parameters.comment
        )

        self.dxlclient.disconnect()

        self.logger.info("Event successfully sent.")

        self.acknowledge_message()

BOT = TIEOutputBot
