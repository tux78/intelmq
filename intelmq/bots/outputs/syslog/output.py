# -*- coding: utf-8 -*-
"""
SyslogOutputBot forwards data to Syslog Server

Parameters:
syslog_ip: IP Address of Syslog Server
syslog_port: port of syslog server
syslog_proto: protocol (UDP|TCP) to be used

"""

import socket,time
from datetime import datetime

from intelmq.lib.bot import Bot
from intelmq.lib.exceptions import MissingDependencyError
import intelmq.lib.utils as utils

class SyslogOutputBot(Bot):

    def init(self):
        self.socket = None
        self.server = self.parameters.syslog_ip
        self.port = self.parameters.syslog_port
        self.maxMessageLength = 1024

        if self.parameters.syslog_proto.upper() == 'UDP':
            self.proto = socket.SOCK_DGRAM
        elif self.parameters.syslog_proto.upper() == 'TCP':
            self.proto = socket.SOCK_STREAM

    def connect(self):
        if self.socket == None:
            r = socket.getaddrinfo(self.server, self.port, socket.AF_UNSPEC, self.proto) 
            if r == None:
                return False
			
            for (addr_fam, sock_kind, proto, ca_name, sock_addr) in r:
                self.socket = socket.socket(addr_fam, self.proto)
                if self.socket == None:
                    return False

                try:
                    self.socket.connect(sock_addr)
                    return True

                except socket.timeout as e:
                    if self.socket != None:
                        self.socket.close()
                        self.socket = None
                        continue

            return False
        else:
            return True

    def close(self) -> None:
        if self.socket != None:
            self.socket.close()
            self.socket = None

    def send(self, messagedata:str) -> None:
        if self.socket != None or self.connect():
            try:
                if self.maxMessageLength != None:
                    self.socket.sendall(messagedata[:self.maxMessageLength])
                else:
                    self.socket.sendall(messagedata)
            except IOError as e:
                self.close()

    def log(self, event, msgid:str='-'):

        pri = 14 # User + Info
        version = 1
        timestamp_s = datetime.utcnow().isoformat()+'Z'
        hostname_s = socket.getfqdn()
        if hostname_s == None:
            hostname_s = socket.gethostname()

        appname_s = "intelMQ" 
        procid_s = "-"
        msgid_s = msgid

        message_s = ''
        content = event.to_dict()
        for key, value in content.items():
            if key != 'raw':
                message_s = message_s + '|' + key + '=' + str(value)

        d = "<%i>%i %s %s %s %s %s %s\n" % (
            pri,
            version,
            timestamp_s,
            hostname_s,
            appname_s,
            procid_s,
            msgid_s,
            message_s
        )

        self.send(d.encode('utf-8'))

    def process(self):
        event = self.receive_message()
        raw_event = utils.base64_decode(event.get('raw'))
        self.log(event, '-')
        self.acknowledge_message()

BOT = SyslogOutputBot
