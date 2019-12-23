# -*- coding: utf-8 -*-
"""
An output but for writing ATD IOCs from RAW to MISP.

Parameters:
  - misp_url: URL of the MISP server
  - misp_key: API key for accessing MISP
  - misp_verify: true or false, check the validity of the certificate
  - misp_distribution: ranges from 0 to 4 (default 0) (Your organization only, This community only, Connected communities, All communities, Sharing Group)
  - atd_event_publish: true or false, if tru publish the atd event in MISP (default false)
  - atd_verdict_severity: defines the minimum severity of reports to be parsed severity ranges from 1 to 5
  

"""
import urllib3
import json
from urllib.parse import urljoin
import intelmq.lib.utils as utils

from intelmq.lib.bot import Bot

try:
    from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute, MISPTag, MISPObject
except ImportError:
    ExpandedPyMISP = None


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

class OutputMISPBot(Bot):

    def init(self):
        if ExpandedPyMISP is None:
            raise ValueError('Could not import pymisp. Please install it.')

        # Initialize MISP connection
        self.misp = ExpandedPyMISP(self.parameters.misp_url,
                           self.parameters.misp_key,
                           self.parameters.misp_verify)

        # Handle the InsecureRequestWarning
        if not self.parameters.misp_verify: urllib3.disable_warnings()
        self.logger.info ("Connected to MISP")

    def process(self):
        # Grab raw event
        report = self.receive_message()
        raw_report = utils.base64_decode(report.get('raw'))
        atd_event = json.loads(raw_report)

        if (atd_event['Summary']['Event_Type'] == 'ATD File Report'):
            if (int(atd_event['Summary']['Verdict']['Severity']) >= self.parameters.atd_verdict_severity):
               # Generate MISP Event
               event = self.misp_add_event(atd_event)

               # Add event to MISP instance
               event = self.misp.add_event(event)

               if self.parameters.atd_event_publish:
                    # Publish new MISP event
                    self.misp.publish(event)

        self.acknowledge_message()

    def misp_add_attribute(self, event, a_type, a_value):
        # Create Attribute object in MISP
        misp_attribute = MISPAttribute()

        if a_type: misp_attribute.type = a_type
        if a_value: misp_attribute.value = a_value
        event.add_attribute(misp_attribute.type, misp_attribute.value)

    def misp_add_tag(self, event, a_value):
        # Create Tag object in MISP
        misp_tag = MISPTag()

        if a_value: misp_tag.name = a_value
        event.add_tag(misp_tag)

    def misp_add_fileObject (self, event, filename, md5, sha1, sha256):
        # Create new MISPFileObject
        misp_object = MISPObject (name = 'file')

        # Add attributes
        misp_object.add_attribute("filename", value = filename)
        misp_object.add_attribute("md5", value = md5)
        misp_object.add_attribute("sha1", value = sha1)
        misp_object.add_attribute("sha256", value = sha256)

        # Add MISPFileObject to event
        event.add_object (misp_object)

    def misp_add_event(self, query):
        # Parse out all data from json

        mainfile = query['Summary']['Subject']['Name']
        # Set Distribution = Organization Only
        distribution=self.parameters.misp_distribution
        # Set Threat level = getting the threat level from ATD
        threat_level_id=query['Summary']['Verdict']['Severity']
        # Set Analysis status = completed
        analysis_status=2

        # Creat Event object in MISP
        misp_event = MISPEvent()
        misp_event.info = "McAfee ATD Sandbox Analysis Report - " + mainfile
        misp_event.distribution = distribution
        misp_event.threat_level_id = atd_to_misp_confidence(threat_level_id)
        misp_event.analysis = analysis_status

        # Add main Information to MISP
        atdip = query['Summary']['ATD IP']
        if not atdip: pass
        else: self.misp_add_attribute(misp_event, "comment", "ATD IP " + atdip)

        dstip = query['Summary']['Dst IP']
        if not dstip: pass
        else: self.misp_add_attribute(misp_event, "ip-dst", dstip)

        taskid = query['Summary']['TaskId']
        if not taskid: pass
        else: self.misp_add_attribute(misp_event, "comment", "ATD TaskID: " + taskid)

        size = query['Summary']['Subject']['size']
        if not size: pass
        else: self.misp_add_attribute(misp_event, "comment", "File size is " + size)

        verdict = query['Summary']['Verdict']['Description']
        if not verdict: pass
        else: self.misp_add_attribute(misp_event, "comment", verdict)

        # Add file object to MISP Event
        self.misp_add_fileObject (misp_event, mainfile, 
            query['Summary']['Subject']['md5'],
            query['Summary']['Subject']['sha-1'],
            query['Summary']['Subject']['sha-256']
        )

        # Add process information to MISP
        try:
            for processes in query['Summary']['Processes']:
                name = processes['Name']
                md5 = processes['Md5']
                sha1 = processes['Sha1']
                sha256 = processes['Sha256']
                if not name: pass
                else: self.misp_add_attribute(misp_event, "filename", name)
                if not md5: pass
                else: self.misp_add_attribute(misp_event, "md5", md5)
                if not sha1: pass
                else: self.misp_add_attribute(misp_event, "sha1", sha1)
                if not sha256: pass
                else: self.misp_add_attribute(misp_event, "sha256", sha256)
        except:
            pass

        # Add files information to MISP
        try:
            for files in query['Summary']['Files']:

                # Evaluate attributes
                name = files['Name']
                md5 = files['Md5']
                sha1 = files['Sha1']
                sha256 = files['Sha256']

                # Add attributes as FileObject to event
                self.misp_add_fileObject (misp_event, name, md5, sha1, sha256)
        except:
            pass

        # Add URL information to MISP
        try:
            for url in query['Summary']['Urls']:
                url = url['Url']
                if not url: pass
                else: self.misp_add_attribute(misp_event, "url", url)
        except:
            pass

        # Add ips information to MISP
        try:
            for ips in query['Summary']['Ips']:
                ipv4 = ips['Ipv4']
                port = ips['Port']
                if not ipv4: pass
                else: self.misp_add_attribute(misp_event, "ip-dst", ipv4)
                if not port: pass
                else: self.misp_add_attribute(misp_event, "url", ipv4 + ":" + port)
        except:
            pass

        # Add stats Information to MISP
        try:
            for stats in query['Summary']['Stats']:
                category = stats['Category']
                if not category: pass
                else: self.misp_add_attribute(misp_event, "comment", category)
        except:
            pass

        # Add behaviour information to MISP
        try:
            for behave in query['Summary']['Behavior']:
                behave = behave['Analysis']
                if not category: pass
                else: self.misp_add_attribute(misp_event, "comment", behave)
        except:
            pass

        # Add Confidence level from ATD to MISP
        self.misp_add_tag(misp_event, str(atd_to_veris_confidence(threat_level_id)))
        # Add TLP info to MISP
        self.misp_add_tag(misp_event, str("tlp:amber"))
        self.misp_add_tag(misp_event, str("McAfee ATD Analysis"))
        # Add tag to event
        self.misp_add_tag(misp_event, str("cssa:origin=\"sandbox\""))
        self.misp_add_tag(misp_event, str("cssa:sharing-class=\"unvetted\""))

        # Add actual event to MISP instance
        # Moved to calling routine
        # misp_event = self.misp.add_event(misp_event)
        return misp_event

BOT = OutputMISPBot
