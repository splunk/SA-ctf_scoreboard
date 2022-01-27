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

from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path

@Configuration()
class getanswerCommand(StreamingCommand):
    def stream(self, records):
        '''
        Configure the logger. In this custom search command we only need to write to scoreboard_admin.log.
        '''
        logger_admin = self.setup_logger(logging.INFO, 'scoreboard_admin.log')

        '''
        Get the session key and username of the currently loged in user, and use them to grab the ctf_users lookup and determine team name.
        '''
        session_key = self._metadata.searchinfo.session_key
        user = self._metadata.searchinfo.username
        users_string = self.get_kv_lookup(logger_admin, 'ctf_users', session_key, 'SA-ctf_scoreboard')
        user_list = json.loads(users_string)
        for user_dict in user_list:

            if 'Username' not in user_dict:
                user_dict['Username'] = ''
            if 'DisplayUsername' not in user_dict:
                user_dict['DisplayUsername'] = ''
            if 'Team' not in user_dict:
                user_dict['Team'] = ''

            if user_dict['Username'] == user:
                if user_dict['Team'] != '':
                    myteam = user_dict['Team']
                elif user_dict['DisplayUsername'] != '':
                    myteam = user_dict['DisplayUsername']
                else:
                    myteam = user

        try:
            myteam
        except NameError:
            myteam = user

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

        '''
        Now use those creds to run a Splunk search to retrieve all the hints.
        '''

        try:
            kwargs_oneshot = {'count': 0}

            searchquery_oneshot = '|inputlookup ctf_hints | dedup Number HintNumber'

            service = client.connect(host='127.0.0.1', port=8089, username=USER, password=PASSWORD)
            oneshotsearch_results = service.jobs.oneshot(searchquery_oneshot, **kwargs_oneshot)
            reader = results.ResultsReader(oneshotsearch_results)
            ctf_hints = []
            for hint in reader:
                ctf_hints.append(hint)


        except:
            logger_admin.exception('Error retrieving hints.')

        '''Enrich hint entitlements with actual Hint text and Team, and filter for this teams hints only.'''

        try:
            kwargs_oneshot = {'count': 0}

            searchquery_oneshot = '''| inputlookup ctf_hint_entitlements 
                                    | lookup ctf_hints Number HintNumber
                                    | lookup ctf_users Username as user
                                    | eval Team=if(Team != "", Team, DisplayUsername)
                                    | eval Team=if(Team != "", Team, Username)
                                    | eval Team=if(Team != "", Team, user)
                                    | dedup Team Number HintNumber
                                    | search Team="''' + myteam + '"'

            service = client.connect(host='127.0.0.1', port=8089, username=USER, password=PASSWORD)
            oneshotsearch_results = service.jobs.oneshot(searchquery_oneshot, **kwargs_oneshot)
            reader = results.ResultsReader(oneshotsearch_results)
            enriched_entitlements = []
            for enriched_entitlement in reader:
                enriched_entitlements.append(enriched_entitlement)

        except:
            logger_admin.exception('Error retrieving hint entitlements.')

        '''
        Write the additional field(s).
        '''

        for record in records:
            hints_available = 0
            hints_received = 0
            hints = []

            for hint in ctf_hints:    
                if record['Number'] == hint['Number']:
                    hints_available += 1
                    sanitized_hint = hint
                    sanitized_hint['Hint'] = 'Your team has not purchased this hint yet!'
                    hints.append(sanitized_hint)

            for entitlement in enriched_entitlements:    
                if record['Number'] == entitlement['Number'] and entitlement['Team'] == myteam:
                    for sanitized_hint in hints:
                        if sanitized_hint['HintNumber'] == entitlement['HintNumber']:
                            sanitized_hint['Hint'] = entitlement['Hint']
                            hints_received += 1

            record['Hints'] = hints
            record['HintsAvailable'] = hints_available
            record['HintsReceived'] = hints_received
            record
            yield record

    def get_kv_lookup(self, logger_admin, lookup_file, session_key, namespace='lookup_editor', owner=None):
        '''
        Get the contents of a KV store lookup.
        '''

        try:

            if owner is None:
                owner = 'nobody'

            # Get the contents
            _, content = splunk.rest.simpleRequest('/servicesNS/' + owner + '/' + namespace + '/storage/collections/data/' + lookup_file, sessionKey=session_key, getargs={'output_mode': 'json'})

            return content

        except:
            logger_admin.exception('KV store lookup could not be loaded')

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
