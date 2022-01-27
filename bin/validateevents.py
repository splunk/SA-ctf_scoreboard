#!/usr/bin/env python

from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
import splunklib.results as results
import splunklib.client as client
import sys
import urllib.request, urllib.parse, urllib.error
import httplib2
from xml.dom import minidom
import logging
import configparser
import splunk.rest
import json
import random
import validatectf

from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path

@Configuration()
class getanswerCommand(StreamingCommand):
    def stream(self, records):
        '''
        Configure the logger. In this custom search command we only need to write to scoreboard_admin.log.
        '''
        logger_admin = self.setup_logger(logging.INFO, 'scoreboard_admin.log')


        '''
        Use the same configuration file as the python controller. The conf file contains a user
        name and password that is critical to retrieve hint entitlements. This user and password
        allows us to retrieve a second session key below.
        '''
        CONF_FILE = make_splunkhome_path(['etc', 'apps', 'SA-ctf_scoreboard', 'appserver', 'controllers', 'scoreboard_controller.config'])
        Config = configparser.ConfigParser()
        parsed_conf_files = Config.read(CONF_FILE)
        if not CONF_FILE in parsed_conf_files:
            logger_admin.error('Could not read config file: %s' % (CONF_FILE))
        USER = Config.get('ScoreboardController', 'USER')
        PASSWORD = Config.get('ScoreboardController', 'PASS')
        VKEY = Config.get('ScoreboardController', 'VKEY')


        '''
        Write the additional field(s).
        '''

        for record in records:
            validated = '0'

            try:
                vcode = validatectf.makeVCode(VKEY, record['tcode'], record['user'], record['Number'],
                                              record['Result'], record['BasePointsAwarded'],
                                              record['SpeedBonusAwarded'],
                                              record['AdditionalBonusAwarded'], record['Penalty'])
                if record['vcode'] == vcode:
                    validated = '1'
                else:
                    validated = '0'

            except:
                pass

            record['Validated'] = str(validated)

            yield record


    def setup_logger(self, level, filename):
        '''
        Setup a logger for the custom search command.
        '''

        logger = logging.getLogger('splunk.appserver.SA-ctf_scoreboard.customsearch.getanswer.' + filename)
        logger.propagate = False
        logger.setLevel(level)

        file_handler = logging.handlers.RotatingFileHandler(make_splunkhome_path(['var', 'log', 'scoreboard', filename]), maxBytes=25000000, backupCount=5)

        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        return logger

dispatch(getanswerCommand, sys.argv, sys.stdin, sys.stdout, __name__)
