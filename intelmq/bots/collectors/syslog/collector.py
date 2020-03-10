# -*- coding: utf-8 -*-
"""
SyslogCollectorBot listens to syslog messages

Parameters:
syslog_ip: IP Address to listen to, leave empty to listen to all IPs on the system
syslog_port: port to listen to

"""

import base64
import json
import time

from datetime import datetime, timezone
from intelmq.lib.bot import CollectorBot

try:
    import socketserver
except ImportError:
    socketserver = None
    raise

class SyslogCollectorBot(CollectorBot):

    def init(self):
        self.logger.info ("Starting Syslog Collector.")
        if socketserver is None:
            self.logger.info ("Missing Dependency.")
            raise MissingDependencyError("SocketServer")
        self.syslog = None

    def process(self):

        if self.syslog is None:
            try:
                factory = SyslogHandlerFactory (self)
                with socketserver.TCPServer(
                        (self.parameters.syslog_ip,self.parameters.syslog_port),
                        factory.start) as syslog:
                    syslog.serve_forever(poll_interval=0.5)
                    self.logger.info ("Socket created.")
            except (IOError, SystemExit):
                self.logger.error ("Error during socket creation.")
                raise

class SyslogHandlerFactory:
    def __init__(self, bot):
        self._bot = bot    

    def start(self, request, client_address, server):
        # The factory could even pass a different handler at each request!
        # The application could change the handler while the server is running!
        return SingleSyslogHandler(request, client_address, server, self._bot)

class SingleSyslogHandler(socketserver.BaseRequestHandler):
    """ One instance per connection. """

    def __init__(self, request, client_address, server, bot):
        # The GUI must be passed before we call the parent constructor
        # because it actually handles the request and finishes it.
        self._bot = bot
        super().__init__(request, client_address, server)           

    def handle(self):
        data = self.request.recv(1024).strip()
        event = self._bot.new_report()
        event.add ('raw', data)
        self._bot.send_message (event)

BOT = SyslogCollectorBot
