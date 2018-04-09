#!/usr/bin/env python

from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
import splunklib.results as results
import splunklib.client as client
import sys
import urllib
import httplib2
from xml.dom import minidom
import logging
import ConfigParser
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
            if not 'Username' in user_dict:
                logger_admin.error('Corrupted ctf_users table. Check that Username column is defined.')
                next
            if not 'DisplayUsername' in user_dict:
                user_dict['DisplayUsername'] = ''
            if not 'Team' in user_dict:
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
        name and password that is critical to retrieve submitted answers. This user and password
        allows us to retrieve a second session key below.
        '''
        CONF_FILE = make_splunkhome_path(['etc', 'apps', 'SA-ctf_scoreboard', 'appserver', 'controllers', 'scoreboard_controller.config'])
        Config = ConfigParser.ConfigParser()
        parsed_conf_files = Config.read(CONF_FILE)
        if not CONF_FILE in parsed_conf_files:
            logger_admin.error('Could not read config file: %s' % (CONF_FILE))
        USER = Config.get('ScoreboardController', 'USER')
        PASSWORD = Config.get('ScoreboardController', 'PASS')

        '''
        Now use those creds to run a Splunk search to retrieve this teams responses including the answer they provided.
        '''

        try:
            kwargs_oneshot = {'count': 0}

            searchquery_oneshot = 'search earliest=0 latest=now index=scoreboard_admin Result=* Answer=* \
            | lookup ctf_users Username as user \
            | eval Team=if(Team != "", Team, DisplayUsername) \
            | eval Team=if(Team != "", Team, Username) \
            | eval Team=if(Team != "", Team, user) \
            | eval t=_time \
            | search Team="' + myteam + '" \
            | table _time t user DisplayUsername Team Number Answer'

            service = client.connect(host='127.0.0.1', port=8089, username=USER, password=PASSWORD)
            oneshotsearch_results = service.jobs.oneshot(searchquery_oneshot, **kwargs_oneshot)
            reader = results.ResultsReader(oneshotsearch_results)
            submissions = []
            for item in reader:
                submissions.append(item)

        except:
            logger_admin.exception('Error retrieving the teams previously submitted answers.')

        '''
        Write the additional field(s).

        records is the list of events Splunk is providing to this custom search command. For each one we will attempt to
        correlate it with this teams answer submissions that we retrieved above. This can likely be simplified/optimized.
        '''

        for record in records:
            Answer = None
            for submission in submissions:
                if int(float(record['_time'])) == int(float(submission['t'])) and \
                record['Number'] ==  submission['Number'] and \
                record['user'] ==  submission['user']:
                    Answer = submission['Answer']
                    break
            record['Answer'] = Answer
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
