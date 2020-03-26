"""
McAfee NVD Collector Bot
Connects to National Vulnerability Database and loads CVE data
The bot generates one message per CVE

Parameters:
"""

import time
import json, requests
import zipfile, io, datetime, os
from os import path
from pathlib import Path

from intelmq.lib.bot import CollectorBot

class nvdCollectorBot(CollectorBot):

    def init(self):
        self.bookmark = self.parameters.bookmark_file
        self.logger.info("Init done.")

    def process(self):
        if not path.exists(self.bookmark):
            self.logger.info("Downloading initial set of CVEs.")

            # Download and process previous year
            url="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-"+str(datetime.datetime.now().year-1)+".json.zip"
            self._process_cve(self._download_file(url))

            # Download and process current year
            url="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-"+str(datetime.datetime.now().year)+".json.zip"
            self._process_cve(self._download_file(url))

        else:
            if not self._check_bookmark():
                self.logger.info("Start Processing of updated CVEs.")

                url="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.zip"
                self._process_cve(self._download_file (url))
            else:
                self.logger.info("Nothing to do.")

        self._update_bookmark()

    def _check_bookmark(self):
        new_bookmark=self._download_file("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.meta")
        new_bookmark = new_bookmark.content.splitlines()[4].decode().split(":")[1]

        old_bookmark = self._process_bookmark (self.bookmark)
        return (new_bookmark == old_bookmark)

    def _process_bookmark(self, filename: str = None, bookmark: str = None):
        if bookmark is not None:
            action = 'w+'
        else:
            action = 'r+'

        try:
            file = open(filename, mode=action, encoding='utf-8')
        except FileNotFoundError:  # directory does not exist
            path = Path(os.path.dirname(filename))
            try:
                path.mkdir(mode=0o755, parents=True, exist_ok=True)
            except IOError:
                self.logger.exception('Directory %r could not be created.', path)
                self.stop()
            else:
                file = open(filename, mode='a+', encoding='utf-8')
        if bookmark is not None:
            file.write(bookmark)
            file.close()
        else:
            retVal = file.read()
            file.close()
            return retVal

    def _download_file (self, url):
        r_file = requests.get(url, stream=True)
        return r_file

    def _process_cve (self, file):
        archive = zipfile.ZipFile(io.BytesIO(file.content))
        jsonfile = archive.open(archive.namelist()[0])
        cve_dict = json.loads(jsonfile.read())

        for cve in cve_dict["CVE_Items"]:
            event = self.new_report()
            event.add("raw", json.dumps(cve))

            self.send_message(event)

    def _update_bookmark (self):
        new_bookmark=self._download_file("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.meta")
        new_bookmark = new_bookmark.content.splitlines()[4].decode().split(":")[1]

        self._process_bookmark (self.bookmark, new_bookmark)

BOT = nvdCollectorBot
