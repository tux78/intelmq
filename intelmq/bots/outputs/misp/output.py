# -*- coding: utf-8 -*-
"""
An output but for writing ATD IOCs from RAW to MISP.

Parameters:
  - misp_url: URL of the MISP server
  - misp_key: API key for accessing MISP
  - misp_verify: true or false, check the validity of the certificate

"""
import json
from urllib.parse import urljoin
import intelmq.lib.utils as utils

from intelmq.lib.bot import Bot

try:
    from pymisp import PyMISP
except ImportError:
    PyMISP = None


def atd_to_veris_confidence(x):
                        return{
                                '2':"veris:confidence=\"Low\"",
                                '3':"veris:confidence=\"Medium\"",
                                '4':"veris:confidence=\"Medium\"",
                                '5':"veris:confidence=\"High\""
                        }.get(x,"veris:confidence=\"None\"")

def atd_to_misp_confidence(x):
                        return{
                                '1':4,
                                '2':3,
                                '3':2,
                                '4':2,
                                '5':1
                        }.get(x,4)

class MISPOutputBot(Bot):

    def init(self):
        if PyMISP is None:
            raise ValueError('Could not import pymisp. Please install it.')

        # Initialize MISP connection
        self.misp = PyMISP(self.parameters.misp_url,
                           self.parameters.misp_key,
                           self.parameters.misp_verify)

    def process(self):
        # Grab raw event
        report = self.receive_message()
        raw_report = utils.base64_decode(report.get('raw'))
        atd_event = json.loads(raw_report)

        if (atd_event['Summary']['Event_Type'] == 'ATD File Report'):
            # Generate MISP Event
            misp_event = self.create_misp_event(atd_event)

            # Publish new MISP event
            self.misp.publish(misp_event)

        self.acknowledge_message()

    def create_misp_event(self, query):
        # Parse out all data from json

        mainfile = query['Summary']['Subject']['Name']
        # Set Distribution = Connected
        distribution=2
        # Set Threat level = getting the threat level from ATD
        threat_level_id=query['Summary']['Verdict']['Severity']
        # Set Analysis status = completed
        analysis_status=2

        # Create New Event in MISP
        event = self.misp.new_event(distribution, 
                                    atd_to_misp_confidence(threat_level_id),
                                    analysis_status,
                                    info="McAfee ATD Sandbox Analysis Report - " + mainfile)

        self.misp.add_named_attribute(event, "filename", mainfile)

        # Add main Information to MISP
        atdip = query['Summary']['ATD IP']
        if not atdip: pass
        else: self.misp.add_named_attribute(event, "comment", "ATD IP " + atdip)

        dstip = query['Summary']['Dst IP']
        if not dstip: pass
        else: self.misp.add_named_attribute(event, "ip-dst", dstip)

        taskid = query['Summary']['TaskId']
        if not taskid: pass
        else: self.misp.add_named_attribute(event, "comment", "ATD TaskID: " + taskid)

        md5 = query['Summary']['Subject']['md5']
        if not md5: pass
        else: self.misp.add_named_attribute(event, "md5", md5)

        sha1 = query['Summary']['Subject']['sha-1']
        if not sha1: pass
        else: self.misp.add_named_attribute(event, "sha1", sha1)

        sha256 = query['Summary']['Subject']['sha-256']
        if not sha256: pass
        else: self.misp.add_named_attribute(event, "sha256", sha256)

        size = query['Summary']['Subject']['size']
        if not size: pass
        else: self.misp.add_named_attribute(event, "comment", "File size is " + size)

        verdict = query['Summary']['Verdict']['Description']
        if not verdict: pass
        else: self.misp.add_named_attribute(event, "comment", verdict)

        # Add process information to MISP
        try:
            for processes in query['Summary']['Processes']:
                name = processes['Name']
                md5 = processes['Md5']
                sha1 = processes['Sha1']
                sha256 = processes['Sha256']
                if not name: pass
                else: self.misp.add_named_attribute(event, "filename", name)
                if not md5: pass
                else: self.misp.add_named_attribute(event, "md5", md5)
                if not sha1: pass
                else: self.misp.add_named_attribute(event, "sha1", sha1)
                if not sha256: pass
                else: self.misp.add_named_attribute(event, "sha256", sha256)
        except:
            pass

        # Add files information to MISP
        try:
            for files in query['Summary']['Files']:
                name = files['Name']
                md5 = files['Md5']
                sha1 = files['Sha1']
                sha256 = files['Sha256']
                if not name: pass
                else: self.misp.add_named_attribute(event, "filename", name)
                if not md5: pass
                else: self.misp.add_named_attribute(event, "md5", md5)
                if not sha1: pass
                else: self.misp.add_named_attribute(event, "sha1", sha1)
                if not sha256: pass
                else: self.misp.add_named_attribute(event, "sha256", sha256)
        except:
            pass

        # Add URL information to MISP
        try:
            for url in query['Summary']['Urls']:
                url = url['Url']
                if not url: pass
                else: self.misp.add_named_attribute(event, "url", url)
        except:
            pass

        # Add ips information to MISP
        try:
            for ips in query['Summary']['Ips']:
                ipv4 = ips['Ipv4']
                port = ips['Port']
                if not ipv4: pass
                else: self.misp.add_named_attribute(event, "ip-dst", ipv4)
                if not port: pass
                else: self.misp.add_named_attribute(event, "url", ipv4 + ":" + port)
        except:
            pass

        # Add stats Information to MISP
        try:
            for stats in query['Summary']['Stats']:
                category = stats['Category']
                if not category: pass
                else: self.misp.add_named_attribute(event, "comment", category)
        except:
            pass

        # Add behaviour information to MISP
        try:
            for behave in query['Summary']['Behavior']:
                behave = behave['Analysis']
                if not category: pass
                else: self.misp.add_named_attribute(event, "comment", behave)
        except:
            pass

        # Add Confidence level from ATD to MISP
        self.misp.add_tag(event, str(atd_to_veris_confidence(threat_level_id)))

        # Add TLP info to MISP
        self.misp.add_tag(event, str("tlp:amber"))

        # Add tag to event
        self.misp.add_tag(event, str("cssa:origin=\"sandbox\""))
        self.misp.add_tag(event, str("cssa:sharing-class=\"unvetted\""))

        return event

BOT = MISPOutputBot

