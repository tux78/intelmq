# -*- coding: utf-8 -*-
"""
pymongo library automatically tries to reconnect if connection has been lost.
"""

import dateutil.parser

from intelmq.lib.bot import Bot

try:
    import pymongo
except ImportError:
    pymongo = None


class MongoDBOutputBot(Bot):
    client = None

    def init(self):
        if pymongo is None:
            raise ValueError('Could not import pymongo. Please install it.')

        self.pymongo_3 = pymongo.version_tuple >= (3, )
        self.pymongo_35 = pymongo.version_tuple >= (3, 5)

        self.replacement_char = getattr(self.parameters, 'replacement_char', '_')
        if self.replacement_char == '.':
            raise ValueError('replacement_char should be different than .')

        self.username = getattr(self.parameters, "db_user", None)
        self.password = getattr(self.parameters, "db_pass", None)
        if not self.password:  # checking for username is sufficient then
            self.username = None

        self.connect()

    def connect(self):
        self.logger.debug('Connecting to MongoDB server.')
        try:
            if self.pymongo_35 and self.username:
                self.client = pymongo.MongoClient(self.parameters.host,
                                                  int(self.parameters.port),
                                                  username=self.username,
                                                  password=self.password)
            else:
                self.client = pymongo.MongoClient(self.parameters.host,
                                                  int(self.parameters.port))
        except pymongo.errors.ConnectionFailure:
            raise ValueError('Connection to MongoDB server failed.')
        else:
            db = self.client[self.parameters.database]
            if self.username and not self.pymongo_35:
                self.logger.debug('Trying to authenticate to database %s.',
                                  self.parameters.database)
                try:
                    db.authenticate(name=self.parameters.db_user,
                                    password=self.parameters.db_pass)
                except pymongo.errors.OperationFailure:
                    raise ValueError('Authentication to database {} failed'.format(self.parameters.database))
            self.collection = db[self.parameters.collection]
            self.logger.info('Successfully connected to MongoDB server.')

    def process(self):
        event = self.receive_message()

        if self.parameters.hierarchical_output:
            tmp_dict = event.to_dict(hierarchical=True)
            if "time"in tmp_dict:
                if "observation" in tmp_dict["time"]:
                    tmp_dict["time"]["observation"] = dateutil.parser.parse(tmp_dict["time"]["observation"])
                if "source" in tmp_dict["time"]:
                    tmp_dict["time"]["source"] = dateutil.parser.parse(tmp_dict["time"]["source"])
        else:
            # flat version
            # replace . in key by replacement_char
            tmp_dict = {key.replace('.', self.replacement_char): value for key, value in event.to_dict().items()}
            time_obs = "time%sobservation" % self.replacement_char
            if time_obs in tmp_dict:
                tmp_dict[time_obs] = dateutil.parser.parse(tmp_dict[time_obs])
            time_src = "time%source" % self.replacement_char
            if time_src in tmp_dict:
                tmp_dict[time_src] = dateutil.parser.parse(tmp_dict[time_obs])

        try:
            if self.pymongo_3:
                self.collection.insert_one(tmp_dict)
            else:
                self.collection.insert(tmp_dict)
        except pymongo.errors.AutoReconnect:
            self.logger.error('Connection Lost. Connecting again.')
            self.connect()
        else:
            self.acknowledge_message()

    def shutdown(self):
        if self.client:
            self.client.close()


BOT = MongoDBOutputBot
