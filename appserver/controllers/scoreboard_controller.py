# -*- coding: UTF-8 -*-
import logging
import os
import sys
import pprint
import json
import shutil
import csv
import cherrypy
import re
import time
import datetime
import collections
import time
import configparser
import uuid


from splunk import AuthorizationFailed, ResourceNotFound
import splunk.rest
import splunk.appserver.mrsparkle.controllers as controllers
import splunk.appserver.mrsparkle.lib.util as util
import splunk.entity as entity
from splunk.appserver.mrsparkle.lib import jsonresponse
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
from splunk.appserver.mrsparkle.lib.decorators import expose_page

import splunklib.client as client
import splunklib.results as results

import urllib.request, urllib.parse, urllib.error
import httplib2
from time import localtime,strftime
from xml.dom import minidom
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ctf_scoreboard', 'bin']))
import validatectf

bin_dir = os.path.join(util.get_apps_dir(), __file__.split('.')[-2], 'bin')

if not bin_dir in sys.path:
    sys.path.append(dir)

def setup_logger(level, filename):
    '''
    Setup a logger for the controller.
    '''

    logger = logging.getLogger('splunk.appserver.SA-ctf_scoreboard.controllers.scoreboard_controller.' + filename)
    logger.propagate = False
    logger.setLevel(level)

    file_handler = logging.handlers.RotatingFileHandler(make_splunkhome_path(['var', 'log', 'scoreboard', filename]),
                                                        maxBytes=25000000, backupCount=5)

    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger

logger = setup_logger(logging.INFO, 'scoreboard.log')
logger.info('scoreboard_controller loaded. Unique ID={0}'.format(uuid.uuid4()))

logger_admin = setup_logger(logging.INFO, 'scoreboard_admin.log')
logger_admin.info('scoreboard_controller loaded. Unique ID={0}'.format(uuid.uuid4()))

from splunk.models.base import SplunkAppObjModel
from splunk.models.field import BoolField, Field


CONF_FILE = make_splunkhome_path(['etc', 'apps', 'SA-ctf_scoreboard', 'appserver', 'controllers',
                                  'scoreboard_controller.config'])

Config = configparser.ConfigParser()
parsed_conf_files = Config.read(CONF_FILE)
if not CONF_FILE in parsed_conf_files:
    logger_admin.error('Could not read config file: %s' % (CONF_FILE))

USER = Config.get('ScoreboardController', 'USER')
PASSWORD = Config.get('ScoreboardController', 'PASS')
VKEY = Config.get('ScoreboardController', 'VKEY')


class ScoreBoardController(controllers.BaseController):
    '''
    CTF Scoreboard Controller
    '''

    @expose_page(must_login=True, methods=['GET'])
    def purchase_hint(self, **kwargs):
        cherrypy.response.headers['Content-Type'] = 'text/plain'

        user = cherrypy.session['user']['name']
        session_key = cherrypy.session.get('sessionKey')

        users_string = self.get_kv_lookup('ctf_users', 'SA-ctf_scoreboard')
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

        submitted_number_string = kwargs.get('Number')
        submitted_hintnumber_string = kwargs.get('HintNumber')

        if not self.represents_int(submitted_number_string):
            logger_admin.error('Submitted question number %s does not represent an integer.' % (submitted_number_string))
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard/scoreboard_error')), 302)

        if not self.represents_int(submitted_hintnumber_string):
            logger_admin.error('Submitted hint number %s does not represent an integer.' % (submitted_hintnumber_string))
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard/scoreboard_error')), 302)

        '''
        Getting the hints is tricky, we need to authenticate as a different user
        '''
        baseurl = 'https://localhost:8089'

        myhttp = httplib2.Http(disable_ssl_certificate_validation=True)
        try:
            servercontent = myhttp.request(baseurl + '/services/auth/login', 'POST', headers={}, body=urllib.parse.urlencode({'username':USER, 'password':PASSWORD}))[1]
            answersessionkey = minidom.parseString(servercontent).getElementsByTagName('sessionKey')[0].childNodes[0].nodeValue
        except:
            logger_admin.exception('Error retrieving the answers session key.')

        try:
            _, hints_string = splunk.rest.simpleRequest('/servicesNS/' + 'nobody' + '/' + 'SA-ctf_scoreboard_admin' + '/storage/collections/data/' + 'ctf_hints', sessionKey=answersessionkey, getargs={'output_mode': 'json'})
            hint_list = json.loads(hints_string)
        except:
            logger_admin.exception('Error retrieving the ctf_hints lookup.')
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard/scoreboard_error')), 302)

        questions_string = self.get_kv_lookup('ctf_questions', 'SA-ctf_scoreboard')
        question_list = json.loads(questions_string)

        '''
        We can also easily grab the list of users who have accepted the agreement in the same way.
        '''
        accepted_agreement_string = self.get_kv_lookup('ctf_eulas_accepted', 'SA-ctf_scoreboard')
        accepted_agreement_list = json.loads(accepted_agreement_string)
        
        '''
        We want to be very careful about not logging much data if the user has not accepted the agreement, so we'll 
        check here and redirect to an informative error page if they have not agreed.
        '''
        agreed = False
        for accepted_agreement in accepted_agreement_list:
            if accepted_agreement['EulaUsername'] == user:
                agreed = True
                if 'EulaDateAccepted' in accepted_agreement:
                    EulaDateAccepted = accepted_agreement['EulaDateAccepted']
                else:
                    EulaDateAccepted = '0'

                if 'EulaId' in accepted_agreement:
                    EulaId = accepted_agreement['EulaId']
                else:
                    EulaId = '0'

                if 'EulaName' in accepted_agreement:
                    EulaName = accepted_agreement['EulaName']
                else:
                    EulaName = ''

                if 'EulaUsername' in accepted_agreement:
                    EulaUsername = accepted_agreement['EulaUsername']
                else:
                    EulaUsername = ''
                
                break
        
        if not agreed:
            logger_admin.error(str('User {} attempted to play without accepting the user agreement.'.format(user)))
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard/user_agreement_required')), 302)
        

        question_exists = False
        for question in question_list:

            if 'Number' not in question:
                question['Number'] = ''
            if 'Question' not in question:
                question['Question'] = ''

            if question['Number'] == submitted_number_string:
                question_to_return = question['Question'].replace('"', "'")
                question_exists = True
                break

        if not question_exists:
            logger_admin.error('Submitted question number does not exists in ctf_questions: %s' % (submitted_number_string))
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard/scoreboard_error')), 302)

        hint_exists = False
        for hint in hint_list:

            if 'Number' not in hint:
                hint['Number'] = ''
            if 'HintNumber' not in hint:
                hint['HintNumber'] = ''
            if 'Hint' not in hint:
                hint['Hint'] = ''
            if 'HintCost' not in hint:
                hint['HintCost'] = ''

            if hint['Number'] == submitted_number_string and hint['HintNumber'] == submitted_hintnumber_string:
                hint_to_return = hint['Hint']
                penalty_to_return = hint['HintCost']
                hint_exists = True
                break

        if not hint_exists:
            logger_admin.error('Submitted question/hint number combination does not exists in ctf_hints: %s / %s' % (submitted_number_string, submitted_hintnumber_string))
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard/scoreboard_error')), 302)

        '''
        Make sure the team does not already have this entitlement.
        '''
        try:
            kwargs_oneshot = {'count': 0}
            searchquery_oneshot = '| inputlookup ctf_hint_entitlements \
                                    | lookup ctf_hints Number HintNumber \
                                    | lookup ctf_users Username as user \
                                    | eval Team=if(Team != "", Team, DisplayUsername) \
                                    | eval Team=if(Team != "", Team, Username) \
                                    | eval Team=if(Team != "", Team, user)\
                                    | search Team="' + myteam + '"'

            service = client.connect(host='127.0.0.1', port=8089, username=USER, password=PASSWORD)
            oneshotsearch_results = service.jobs.oneshot(searchquery_oneshot, **kwargs_oneshot)
            reader = results.ResultsReader(oneshotsearch_results)
            enriched_entitlements = []
            for enriched_entitlement in reader:
                enriched_entitlements.append(enriched_entitlement)

        except:
            logger_admin.exception('Error retrieving hint entitlements.')

        already_purchased = False
        for enriched_entitlement in enriched_entitlements:

            if 'Number' not in enriched_entitlement:
                enriched_entitlement['Number'] = ''
            if 'HintNumber' not in enriched_entitlement:
                enriched_entitlement['HintNumber'] = ''
            if 'Team' not in enriched_entitlement:
                enriched_entitlement['Team'] = ''

            if enriched_entitlement['Number'] == submitted_number_string and enriched_entitlement['HintNumber'] == submitted_hintnumber_string and enriched_entitlement['Team'] == myteam:
                already_purchased = True

        '''
        We now have all the data to update the ctf_hint_entitlements kvstore, but only if they have not already purchased it.
        '''
        if not already_purchased:
            try:
                uri = '/servicesNS/' + 'nobody' + '/' + 'SA-ctf_scoreboard' + '/storage/collections/data/' + 'ctf_hint_entitlements'
                payload = {
                   'Number': submitted_number_string,
                   'HintNumber': submitted_hintnumber_string,
                   'user' : user
                }
                payload_json = json.dumps(payload)

                response, content = splunk.rest.simpleRequest(uri, method='POST', jsonargs=payload_json, sessionKey=answersessionkey)

            except:
                logger_admin.exception('Error posting to ctf_hint_entitelments lookup.')
                raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard/scoreboard_error')), 302)

        adminoutput = collections.OrderedDict()
        partoutput = collections.OrderedDict()

        partoutput['user'] = str('%s' % (user))
        adminoutput['user'] = str('%s' % (user))

        partoutput['Result'] = str('%s' %  ('Hint'))
        adminoutput['Result'] = str('%s' % ('Hint'))

        partoutput['Number'] = str('%s' % (submitted_number_string))
        adminoutput['Number'] = str('%s' % (submitted_number_string))

        partoutput['HintNumber'] = str('%s' % (submitted_hintnumber_string))
        adminoutput['HintNumber'] = str('%s' % (submitted_hintnumber_string))

        if not already_purchased:
            partoutput['Penalty'] = str('%s' % (penalty_to_return))
            adminoutput['Penalty'] = str('%s' % (penalty_to_return))
        else:
            partoutput['Penalty'] = str('%s' % ('0'))
            adminoutput['Penalty'] = str('%s' % ('0'))

            partoutput['HintAlreadyPurchased'] = str('%s' % ('1'))
            adminoutput['HintAlreadyPurchased'] = str('%s' % ('1'))

        partoutput['Question'] = str('"%s"' % (question_to_return).replace('"', "'"))
        adminoutput['Question'] = str('"%s"' % (question_to_return).replace('"', "'"))

        adminoutput['Hint'] = str('"%s"' % (hint_to_return))

        partoutput['BasePointsAwarded'] = str('%s' % ('0'))
        adminoutput['BasePointsAwarded'] = str('%s' % ('0'))

        partoutput['SpeedBonusAwarded'] = str('%s' % ('0'))
        adminoutput['SpeedBonusAwarded'] = str('%s' % ('0'))

        partoutput['AdditionalBonusAwarded'] = str('%s' % ('0'))
        adminoutput['AdditionalBonusAwarded'] = str('%s' % ('0'))

        partoutput['EulaDateAccepted'] = str('%s' % (EulaDateAccepted))
        adminoutput['EulaDateAccepted'] = str('%s' % (EulaDateAccepted))

        partoutput['EulaId'] = str('%s' % (EulaId))
        adminoutput['EulaId'] = str('%s' % (EulaId))

        partoutput['EulaName'] = str('%s' % (EulaName))
        adminoutput['EulaName'] = str('%s' % (EulaName))

        partoutput['EulaUsername'] = str('%s' % (EulaUsername))
        adminoutput['EulaUsername'] = str('%s' % (EulaUsername))


        tcode = validatectf.makeTCode(int(time.time()))
        partoutput['tcode'] = str('%s' % (tcode))
        adminoutput['tcode'] = str('%s' % (tcode))

        try:
            vcode = validatectf.makeVCode(VKEY, tcode, partoutput['user'], partoutput['Number'], partoutput['Result'], partoutput['BasePointsAwarded'], partoutput['SpeedBonusAwarded'],partoutput['AdditionalBonusAwarded'],partoutput['Penalty'])
            partoutput['vcode'] = str('%s' % (vcode))
            adminoutput['vcode'] = str('%s' % (vcode))
        except:
            logger_admin.exception(str('Exception raised in makeVCode'))

        adminoutputlist = []
        partoutputlist = []
        partoutputlisturl = []

        for k,v in list(adminoutput.items()):
            v.replace(',', '')
            adminoutputlist.append(str('%s=%s' % (k,v)))

        for k,v in list(partoutput.items()):
            v.replace(',', '')
            partoutputlist.append(str('%s=%s' % (k,v)))
            partoutputlisturl.append(str('%s=%s' % (k,urllib.parse.quote(v.encode('utf8')))))

        logger.info(','.join(partoutputlist))
        logger_admin.info(','.join(adminoutputlist))

        raise cherrypy.HTTPRedirect(str('%s?%s' % ('/en-US/app/SA-ctf_scoreboard/question', '&'.join(partoutputlisturl))), 302)


    @expose_page(must_login=True, methods=['GET'])
    def adjust_score(self, **kwargs):
        cherrypy.response.headers['Content-Type'] = 'text/plain'

        user = cherrypy.session['user']['name']
        session_key = cherrypy.session.get('sessionKey')

        submitted_team_string = kwargs.get('Teams')
        submitted_base = kwargs.get('Base')
        submitted_bonus = kwargs.get('Bonus')
        submitted_penalty = kwargs.get('Penalty')
        submitted_note = kwargs.get('Note')
        submitted_number = kwargs.get('Number')

        content = ''
        user_details= {}

        _, content = splunk.rest.simpleRequest('/services/authentication/users/' + user, sessionKey=session_key, getargs={'output_mode': 'json'})
        user_details = json.loads(content)

        if 'ctf_admin' not in user_details['entry'][0]['content']['roles']:
            logger_admin.error('Unauthorized attempt to adjust a score. %s is not assigned the ctf_admin role.' % (user))
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard_admin/scoreboard_admin_error')), 302)

        if not kwargs.get('Adjust') == 'True':
            logger_admin.error('Request to adjust scores did not include Adjust = True kv pair.')
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard_admin/scoreboard_admin_error')), 302)

        if not submitted_team_string or submitted_team_string=='$Teams$':
            logger_admin.error('Attempted to adjust score but no teams were submitted as part of form request.')
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard_admin/scoreboard_admin_error')), 302)

        if not submitted_bonus and not submitted_penalty:
            logger_admin.error('Attempted to adjust score but no bonus or penalty was submitted as part of request.')
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard_admin/scoreboard_admin_error')), 302)

        if submitted_base and not self.represents_int(submitted_base):
            logger_admin.error('Submitted base score %s does not represent an integer.' % (submitted_base))
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard_admin/scoreboard_admin_error')), 302)

        if submitted_bonus and not self.represents_int(submitted_bonus):
            logger_admin.error('Submitted bonus score %s does not represent an integer.' % (submitted_bonus))
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard_admin/scoreboard_admin_error')), 302)

        if submitted_penalty and not self.represents_int(submitted_penalty):
            logger_admin.error('Submitted penalty score %s does not represent an integer.' % (submitted_penalty))
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard_admin/scoreboard_admin_error')), 302)

        if not submitted_note:
            logger_admin.error('Attempted to adjust score but no note was submitted as part of request.')
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard_admin/scoreboard_admin_error')), 302)

        if not self.represents_int(submitted_number):
            logger_admin.error(str('Value submitted for "Number" (%s) does not represent a number.' % submitted_number))
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard_admin/scoreboard_admin_error')), 302)

        if int(submitted_number) < 1 or int(submitted_number) > 1024:
            logger_admin.error(str('That number is not cool, bro. (%s). Must be between 1 and 1024 inclusive.' % submitted_number))
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard_admin/scoreboard_admin_error')), 302)

        partoutput = {}
        adminoutput = {}

        partoutput['admin_user'] = str('%s' % (user))
        adminoutput['admin_user'] = str('%s' % (user))

        partoutput['Adjustment'] = str('%s' % ('True'))
        adminoutput['Adjustment'] = str('%s' % ('True'))

        partoutput['Note'] = str('"%s"' % (submitted_note))
        adminoutput['Note'] = str('"%s"' % (submitted_note))

        questions_string = self.get_kv_lookup('ctf_questions', 'SA-ctf_scoreboard')
        question_list = json.loads(questions_string)

        for question_dict in question_list:
            if question_dict['Number'] == submitted_number:
                adminoutput['QuestionOfficial'] = str('"%s"' % (question_dict['Question'].replace('"', "'")))
                partoutput['QuestionOfficial'] = str('"%s"' % (question_dict['Question'].replace('"', "'")))

                adminoutput['BasePointsAvailable'] = str('%s' % (question_dict['BasePoints']))
                partoutput['BasePointsAvailable'] = str('%s' % (question_dict['BasePoints']))

                basepoints = question_dict['BasePoints']

                adminoutput['StartTime'] = str('%s' % (question_dict['StartTime']))
                partoutput['StartTime'] = str('%s' % (question_dict['StartTime']))

                adminoutput['EndTime'] = str('%s' % (question_dict['EndTime']))
                partoutput['EndTime'] = str('%s' % (question_dict['EndTime']))

                found_question = True

                break

        if not found_question:
            logger_admin.error(str('Could not find question with number (%s)' % submitted_number))
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard_admin/scoreboard_admin_error')), 302)

        submitted_team_list = submitted_team_string.split()

        for team in submitted_team_list:
            try:
                content = ''
                user_details= {}

                _, content = splunk.rest.simpleRequest('/services/authentication/users/' + team, sessionKey=session_key, getargs={'output_mode': 'json'})
                user_details = json.loads(content)
                if 'ctf_competitor' not in user_details['entry'][0]['content']['roles']:
                    logger_admin.error('Submitted user %s is not assigned the ctf_competitor role.')
                    raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard_admin/scoreboard_admin_error')), 302)

                adminoutput['BasePointsAwarded'] = str('0')
                adminoutput['user'] = str(team)
                adminoutput['Number'] = str(submitted_number)

                partoutput['BasePointsAwarded'] = str('0')
                partoutput['user'] = str(team)
                partoutput['Number'] = str(submitted_number)

                if submitted_base or submitted_bonus:
                    adminoutput['Result'] = str('Correct')
                    partoutput['Result'] = str('Correct')

                    adminoutput['SpeedBonusAwarded'] = str(submitted_bonus)
                    partoutput['SpeedBonusAwarded'] = str(submitted_bonus)

                    adminoutput['BasePointsAwarded'] = str(submitted_base)
                    partoutput['BasePointsAwarded'] = str(submitted_base)

                    adminoutput['AdditionalBonusAwarded'] = str('0')
                    partoutput['AdditionalBonusAwarded'] = str('0')

                    adminoutput['Penalty'] = str('0')
                    partoutput['Penalty'] = str('0')

                    tcode = validatectf.makeTCode(int(time.time()))
                    partoutput['tcode'] = str('%s' % (tcode))
                    adminoutput['tcode'] = str('%s' % (tcode))

                    try:
                        vcode = validatectf.makeVCode(VKEY, tcode, partoutput['user'], partoutput['Number'],
                                                      partoutput['Result'], partoutput['BasePointsAwarded'],
                                                      partoutput['SpeedBonusAwarded'],
                                                      partoutput['AdditionalBonusAwarded'], partoutput['Penalty'])
                        partoutput['vcode'] = str('%s' % (vcode))
                        adminoutput['vcode'] = str('%s' % (vcode))
                    except:
                        logger_admin.exception(str('Exception raised in makeVCode'))

                    adminoutputlist = []
                    partoutputlist = []
                    partoutputlisturl = []

                    for k,v in list(adminoutput.items()):
                        v.replace(',', '')
                        adminoutputlist.append(str('%s=%s' % (k,v)))

                    for k,v in list(partoutput.items()):
                        v.replace(',', '')
                        partoutputlist.append(str('%s=%s' % (k,v)))
                        partoutputlisturl.append(str('%s=%s' % (k,urllib.parse.quote(v.encode('utf8')))))

                    logger.info(','.join(partoutputlist))
                    logger_admin.info(','.join(adminoutputlist))

                if submitted_penalty:
                    adminoutput['Result'] = str('Incorrect')
                    partoutput['Result'] = str('Incorrect')

                    adminoutput['Penalty'] = str(submitted_penalty)
                    partoutput['Penalty'] = str(submitted_penalty)

                    adminoutput['SpeedBonusAwarded'] = str('0')
                    partoutput['SpeedBonusAwarded'] = str('0')

                    adminoutput['BasePointsAwarded'] = str('0')
                    partoutput['BasePointsAwarded'] = str('0')

                    adminoutput['AdditionalBonusAwarded'] = str('0')
                    partoutput['AdditionalBonusAwarded'] = str('0')

                    tcode = validatectf.makeTCode(int(time.time()))
                    partoutput['tcode'] = str('%s' % (tcode))
                    adminoutput['tcode'] = str('%s' % (tcode))

                    try:
                        vcode = validatectf.makeVCode(VKEY, tcode, partoutput['user'], partoutput['Number'],
                                                      partoutput['Result'], partoutput['BasePointsAwarded'],
                                                      partoutput['SpeedBonusAwarded'],
                                                      partoutput['AdditionalBonusAwarded'], partoutput['Penalty'])
                        partoutput['vcode'] = str('%s' % (vcode))
                        adminoutput['vcode'] = str('%s' % (vcode))
                    except:
                        logger_admin.exception(str('Exception raised in makeVCode'))

                    adminoutputlist = []
                    partoutputlist = []
                    partoutputlisturl = []

                    for k,v in list(adminoutput.items()):
                        v.replace(',', '')
                        adminoutputlist.append(str('%s=%s' % (k,v)))

                    for k,v in list(partoutput.items()):
                        v.replace(',', '')
                        partoutputlist.append(str('%s=%s' % (k,v)))
                        partoutputlisturl.append(str('%s=%s' % (k,urllib.parse.quote(v.encode('utf8')))))

                    logger.info(','.join(partoutputlist))
                    logger_admin.info(','.join(adminoutputlist))


            except:
                logger_admin.exception('An exception occurred.')
                raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard_admin/scoreboard_admin_error')), 302)

        raise cherrypy.HTTPRedirect(str('%s?%s' % ('/en-US/app/SA-ctf_scoreboard_admin/adjust_score_result', '&'.join(partoutputlisturl))), 302)


    @expose_page(must_login=True, methods=['GET'])
    def submit_question(self, **kwargs):

        '''
        Ultimately we will return a web page, and the content type will be text/plain as it will just be
        a 302 redirect to Splunk dashboard. 
        '''

        cherrypy.response.headers['Content-Type'] = 'text/plain'

        '''
        Important to grab the Splunk user from the CherryPy framework embedded ithin splunk.
        '''

        user = cherrypy.session['user']['name']

        '''
        Getting the answers is tricky, we need to authenticate as a different user
        '''

        '''
        The Splunkd port. It's a best practice to close access to this from the outside world during a competition 
        but it's always available locally.
        '''
        baseurl = 'https://localhost:8089'

        '''urllib2 wants to enforce trusted certs, but splunkd cert is always self-signed.'''
        myhttp = httplib2.Http(disable_ssl_certificate_validation=True)

        '''
        Authenticate to the Splunkd REST API using the creds retreived from the scoreboard config file. 
        The session key we are after is buried in an XML response so we extract it using minidom.
        If anything goes wrong we just log that to scoreboard_admin.log. FYI is something goes wrong here we're 
        in major trouble.
        '''
        try:
            servercontent = myhttp.request(baseurl + '/services/auth/login', 'POST', headers={},
                                           body=urllib.parse.urlencode({'username':USER, 'password':PASSWORD}))[1]
            answersessionkey = minidom.parseString(servercontent).getElementsByTagName('sessionKey')[0].childNodes[0].nodeValue
        except:
            logger_admin.exception('Error retrieving the privileged session key.')

        '''
        Now we use the privileged session key retrieved above to retrieve the ctf_answers lookup which is in the form
        of a KV store collection. We grab it as a json string then load it into a python list of dictionaries.
        If anything goes wrong here, we log to scoreboard_admin.log and redirect the user to the standard error page.
        One of the things that could have gone wrong here is we did not retrieve a valid session key from the config 
        file using the code directly above. 
        '''
        try:
            _, answers_string = splunk.rest.simpleRequest('/servicesNS/' + 'nobody' + '/' + 'SA-ctf_scoreboard_admin' +
                                                          '/storage/collections/data/' + 'ctf_answers',
                                                          sessionKey=answersessionkey, getargs={'output_mode': 'json'})
            answer_list = json.loads(answers_string)
        except:
            logger_admin.exception('Error retrieving the answers lookup. Check the controller config file credentials and that ctf_answers exists, and has proper permissions.')
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard/scoreboard_error')), 302)

        '''
        It's far easier to grab the questions becasue we can just use the competitors session_key.
        get_kv_lookup is Luke Murphey's code copied from his Lookup File Editor app.
        '''
        questions_string = self.get_kv_lookup('ctf_questions', 'SA-ctf_scoreboard')
        question_list = json.loads(questions_string)

        '''
        We can also easily grab the list of users who have accepted the agreement in the same way.
        '''
        accepted_agreement_string = self.get_kv_lookup('ctf_eulas_accepted', 'SA-ctf_scoreboard')
        accepted_agreement_list = json.loads(accepted_agreement_string)
        
        '''
        We want to be very careful about not logging much data if the user has not accepted the agreement, so we'll 
        check here and redirect to an informative error page if they have not agreed.
        '''
        agreed = False
        for accepted_agreement in accepted_agreement_list:
            if accepted_agreement['EulaUsername'] == user:
                agreed = True
                if 'EulaDateAccepted' in accepted_agreement:
                    EulaDateAccepted = accepted_agreement['EulaDateAccepted']
                else:
                    EulaDateAccepted = '0'

                if 'EulaId' in accepted_agreement:
                    EulaId = accepted_agreement['EulaId']
                else:
                    EulaId = '0'

                if 'EulaName' in accepted_agreement:
                    EulaName = accepted_agreement['EulaName']
                else:
                    EulaName = ''

                if 'EulaUsername' in accepted_agreement:
                    EulaUsername = accepted_agreement['EulaUsername']
                else:
                    EulaUsername = ''
                
                break
        
        if not agreed:
            logger_admin.error(str('User {} attempted to play without accepting the user agreement.'.format(user)))
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard/user_agreement_required')), 302)
        
        '''
        Now we have the questions and the answers. (oh and the Agreements) 
        
        partoutput is an ordered dictionary that contains key-value pairs that will be sent back to the PARTicipant, 
        and treat it as though ALL PARTicipants can see it. No answers, submitted answers, hints, etc. partoutput will
        be logged to scoreboard.log, and indexed into index=scoreboard. Portions of partoutput are also returned
        as URL query string paramters that get displayed to the competitor on a Splunk dashboard.
        
        adminoutput is an ordered dictionary that conatins key-value pairs that competition ADMINS can see. This is 
        where answers, attempted answers, and hints can be safely written. adminoutput will be logged to
        scoreboard_admin.log and indexed to index=scoreboard_admin.
        '''

        partoutput = collections.OrderedDict()
        adminoutput = collections.OrderedDict()

        '''
        First we capture user. This is the Splunk user. It is enriched throughout these apps from the ctf_users
        KVstore collection to derive DsiplayUsername and Team. In this code we only care about the Splunk user.
        '''
        partoutput['user'] = str('%s' % (user))
        adminoutput['user'] = str('%s' % (user))

        '''
        kwargs contains the HTML form element names and their values as submitted by the competitor. Here we iterate
        through them and add to partoutput and adminoutput for ultimate inclusion. We take care to not include the 
        submitted answer in partoutput. 
        '''
        for k,v in kwargs.items():
            if k == 'Answer' or k == 'Question':
                adminoutput[k] = ('"%s"' % (v.replace('"', "'")))
            else:
                adminoutput[k] = ('%s' % (v))

            if k != 'Answer':
                partoutput[k] = ('%s' % (v))

        '''
        For convenience we grab the values that the competitor submitted for Answer and Number.
        We also grab the system time.
        '''
        submitted_answer = kwargs.get('Answer')
        submitted_number = kwargs.get('Number')

        submitted_time = int(time.time())

        '''
        If the Number submitted does not represent an integer, return an error page. This would likely be the result 
        of manipulation of the query string.
        '''

        if not self.represents_int(submitted_number):
            logger_admin.error(str('Value submitted for "Number" (%s) does not represent a number.' % submitted_number))
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard/scoreboard_error')), 302)

        '''
        Now try to find the question that corresponds to the Number submitted by the competitor.
        When we find the match, add almost everything to partoutput and adminoutput.
        We take particular care with the AdditionalBonus fields. They may not exist and we need to handle that 
        situation gracefully.
        If the question number is not found, return an error.
        '''
        found_question = False

        for question_dict in question_list:
            if question_dict['Number'] == submitted_number:
                adminoutput['QuestionOfficial'] = str('"%s"' % (question_dict['Question'].replace('"', "'")))
                partoutput['QuestionOfficial'] = str('"%s"' % (question_dict['Question'].replace('"', "'")))

                adminoutput['BasePointsAvailable'] = str('%s' % (question_dict['BasePoints']))
                partoutput['BasePointsAvailable'] = str('%s' % (question_dict['BasePoints']))

                basepoints = question_dict['BasePoints']

                adminoutput['StartTime'] = str('%s' % (question_dict['StartTime']))
                partoutput['StartTime'] = str('%s' % (question_dict['StartTime']))

                adminoutput['EndTime'] = str('%s' % (question_dict['EndTime']))
                partoutput['EndTime'] = str('%s' % (question_dict['EndTime']))

                if 'AdditionalBonusPoints' not in question_dict:
                    question_dict['AdditionalBonusPoints'] = '0'

                if question_dict['AdditionalBonusPoints'] == '':
                    question_dict['AdditionalBonusPoints'] = '0'

                additionalbonus = question_dict['AdditionalBonusPoints']

                if 'AdditionalBonusInstructions' not in question_dict:
                    question_dict['AdditionalBonusInstructions'] = ''

                additionalbonusinstructions = question_dict['AdditionalBonusInstructions']

                found_question = True

                break

        if not found_question:
            logger_admin.error(str('Could not find question with number (%s)' % submitted_number))
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard/scoreboard_error')), 302)

        for answer_dict in answer_list:
            if answer_dict['Number'] == submitted_number:
                adminoutput['AnswerOfficial'] = str('"%s"' % (answer_dict['Answer'].replace('"', "'")))

                if submitted_answer.lower().strip() == answer_dict['Answer'].lower().strip():

                    adminoutput['Result'] = str('%s' % ('Correct'))
                    partoutput['Result'] = str('%s' % ('Correct'))

                    adminoutput['Penalty'] = str('%s' % ('0'))
                    partoutput['Penalty'] = str('%s' % ('0'))

                    if submitted_time >= int(question_dict['StartTime']) and submitted_time <= int(question_dict['EndTime']):

                        adminoutput['BasePointsAwarded'] = str('%s' % (basepoints))
                        partoutput['BasePointsAwarded'] = str('%s' % (basepoints))

                        seconds_until_end = int(question_dict['EndTime']) - submitted_time
                        question_duration = int(question_dict['EndTime']) - int(question_dict['StartTime'])
                        time_bonus_perc = float(seconds_until_end) / float(question_duration)
                        time_bonus = float(basepoints) * time_bonus_perc
                        time_bonus = int(round(time_bonus))

                        adminoutput['SpeedBonusAwarded'] = str('%s' % (time_bonus))
                        partoutput['SpeedBonusAwarded'] = str('%s' % (time_bonus))

                        if additionalbonus != '0':
                            adminoutput['SolicitBonusInfo'] = str('1')
                            partoutput['SolicitBonusInfo'] = str('1')

                            adminoutput['SolicitBonusInstructions'] = str('"%s"' % (additionalbonusinstructions.replace('"', "'")))
                            partoutput['SolicitBonusInstructions'] = str('"%s"' % (additionalbonusinstructions.replace('"', "'"))) 

                    else:
                        adminoutput['BasePointsAwarded'] = str('%s' % ('0'))
                        partoutput['BasePointsAwarded'] = str('%s' % ('0'))

                        adminoutput['SpeedBonusAwarded'] = str('%s' % ('0'))
                        partoutput['SpeedBonusAwarded'] = str('%s' % ('0'))

                        logger_admin.error(str('Question submitted at {}, but earliest is {} and latest is {}.'.format(submitted_time, question_dict['StartTime'], question_dict['EndTime'])))

                else:
                    adminoutput['Result'] = str('%s' % ('Incorrect'))
                    partoutput['Result'] = str('%s' % ('Incorrect'))

                    adminoutput['BasePointsAwarded'] = str('%s' % ('0'))
                    partoutput['BasePointsAwarded'] = str('%s' % ('0'))

                    adminoutput['SpeedBonusAwarded'] = str('%s' % ('0'))
                    partoutput['SpeedBonusAwarded'] = str('%s' % ('0'))

                    adminoutput['Penalty'] = str('%s' % ('10'))
                    partoutput['Penalty'] = str('%s' % ('10'))

                break

        adminoutput['AdditionalBonusAwarded'] = str('%s' % ('0'))
        partoutput['AdditionalBonusAwarded'] = str('%s' % ('0'))

        partoutput['EulaDateAccepted'] = str('%s' % (EulaDateAccepted))
        adminoutput['EulaDateAccepted'] = str('%s' % (EulaDateAccepted))

        partoutput['EulaId'] = str('%s' % (EulaId))
        adminoutput['EulaId'] = str('%s' % (EulaId))

        partoutput['EulaName'] = str('%s' % (EulaName))
        adminoutput['EulaName'] = str('%s' % (EulaName))

        partoutput['EulaUsername'] = str('%s' % (EulaUsername))
        adminoutput['EulaUsername'] = str('%s' % (EulaUsername))

        tcode = validatectf.makeTCode(int(time.time()))
        partoutput['tcode'] = str('%s' % (tcode))
        adminoutput['tcode'] = str('%s' % (tcode))

        try:
            vcode = validatectf.makeVCode(VKEY, tcode, partoutput['user'], partoutput['Number'], partoutput['Result'], partoutput['BasePointsAwarded'], partoutput['SpeedBonusAwarded'],partoutput['AdditionalBonusAwarded'],partoutput['Penalty'])
            partoutput['vcode'] = str('%s' % (vcode))
            adminoutput['vcode'] = str('%s' % (vcode))
        except:
            logger_admin.exception(str('Exception raised in makeVCode'))

        adminoutputlist = []
        partoutputlist = []
        partoutputlisturl = []

        for k,v in list(adminoutput.items()):
            v.replace(',', '')
            adminoutputlist.append(str('%s=%s' % (k,v)))

        for k,v in list(partoutput.items()):
            v.replace(',', '')
            partoutputlist.append(str('%s=%s' % (k,v)))
            partoutputlisturl.append(str('%s=%s' % (k,urllib.parse.quote(v.encode('utf8')))))

        logger.info(','.join(partoutputlist))
        logger_admin.info(','.join(adminoutputlist))

        raise cherrypy.HTTPRedirect(str('%s?%s' % ('/en-US/app/SA-ctf_scoreboard/result', '&'.join(partoutputlisturl))), 302)


    @expose_page(must_login=True, methods=['GET'])
    def submit_bonus_info(self, **kwargs):
        cherrypy.response.headers['Content-Type'] = 'text/plain'

        user = cherrypy.session['user']['name']

        baseurl = 'https://localhost:8089'

        questions_string = self.get_kv_lookup('ctf_questions', 'SA-ctf_scoreboard')
        question_list = json.loads(questions_string)

        '''
        We can also easily grab the list of users who have accepted the agreement in the same way.
        '''
        accepted_agreement_string = self.get_kv_lookup('ctf_eulas_accepted', 'SA-ctf_scoreboard')
        accepted_agreement_list = json.loads(accepted_agreement_string)
        
        '''
        We want to be very careful about not logging much data if the user has not accepted the agreement, so we'll 
        check here and redirect to an informative error page if they have not agreed.
        '''
        agreed = False
        for accepted_agreement in accepted_agreement_list:
            if accepted_agreement['EulaUsername'] == user:
                agreed = True
                if 'EulaDateAccepted' in accepted_agreement:
                    EulaDateAccepted = accepted_agreement['EulaDateAccepted']
                else:
                    EulaDateAccepted = '0'

                if 'EulaId' in accepted_agreement:
                    EulaId = accepted_agreement['EulaId']
                else:
                    EulaId = '0'

                if 'EulaName' in accepted_agreement:
                    EulaName = accepted_agreement['EulaName']
                else:
                    EulaName = ''

                if 'EulaUsername' in accepted_agreement:
                    EulaUsername = accepted_agreement['EulaUsername']
                else:
                    EulaUsername = ''
                
                break
        
        if not agreed:
            logger_admin.error(str('User {} attempted to play without accepting the user agreement.'.format(user)))
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard/user_agreement_required')), 302)

        partoutput = {}
        adminoutput = {}

        partoutput['user'] = str('%s' % (user))
        adminoutput['user'] = str('%s' % (user))

        for k,v in kwargs.items():

            if k == 'Answer' or k == 'Question':
                adminoutput[k] = ('"%s"' % (v.replace('"', "'")))
            else:
                adminoutput[k] = ('%s' % (v))

            if k != 'Answer' and k != 'BonusInfo':
                partoutput[k] = ('%s' % (v))

        submitted_number = kwargs.get('Number')
        submitted_bonus_info = kwargs.get('BonusInfo')

        submitted_time = int(time.time())

        if not self.represents_int(submitted_number):
            logger_admin.error(str('Value submitted for "Number" (%s) does not represent a number.' % submitted_number))
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard/scoreboard_error')), 302)

        if int(submitted_number) < 1 or int(submitted_number) > 1024:
            logger_admin.error(str('That number is not cool, bro. (%s). Must be between 1 and 1024 inclusive.' % submitted_number))
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard/scoreboard_error')), 302)

        if len(str(submitted_bonus_info)) == 0:
            logger_admin.error(str('Empty bonus string submitted.'))
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard/scoreboard_error')), 302)

        if len(str(submitted_bonus_info)) > 2048:
            logger_admin.error(str('Bonus string submitted longer than 1024 characters.'))
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard/scoreboard_error')), 302)

        found_question = False

        for question_dict in question_list:
            if question_dict['Number'] == submitted_number:
                adminoutput['QuestionOfficial'] = str('"%s"' % (question_dict['Question'].replace('"', "'")))
                partoutput['QuestionOfficial'] = str('"%s"' % (question_dict['Question'].replace('"', "'")))

                adminoutput['BasePointsAvailable'] = str('%s' % (question_dict['BasePoints']))
                partoutput['BasePointsAvailable'] = str('%s' % (question_dict['BasePoints']))

                basepoints = question_dict['BasePoints']

                adminoutput['StartTime'] = str('%s' % (question_dict['StartTime']))
                partoutput['StartTime'] = str('%s' % (question_dict['StartTime']))

                adminoutput['EndTime'] = str('%s' % (question_dict['EndTime']))
                partoutput['EndTime'] = str('%s' % (question_dict['EndTime']))

                if 'AdditionalBonusPoints' not in question_dict:
                    question_dict['AdditionalBonusPoints'] = '0'

                if question_dict['AdditionalBonusPoints'] == '':
                    question_dict['AdditionalBonusPoints'] = '0'

                additionalbonus = question_dict['AdditionalBonusPoints']

                found_question = True

                break

        if not found_question:
            logger_admin.error(str('Could not find question with number (%s)' % submitted_number))
            raise cherrypy.HTTPRedirect(str('%s' % ('/en-US/app/SA-ctf_scoreboard/scoreboard_error')), 302)

        adminoutput['Result'] = str('Bonus')
        partoutput['Result'] = str('Bonus')

        if submitted_time >= int(question_dict['StartTime']) and submitted_time <= int(question_dict['EndTime']):
            adminoutput['AdditionalBonusAwarded'] = str('%s' % (additionalbonus))
            partoutput['AdditionalBonusAwarded'] = str('%s' % (additionalbonus))

        else:
            adminoutput['AdditionalBonusAwarded'] = str('%s' % ('0'))
            partoutput['AdditionalBonusAwarded'] = str('%s' % ('0'))
            logger_admin.error(str('Question submitted at {}, but earliest is {} and latest is {}.'.format(submitted_time, question_dict['StartTime'], question_dict['EndTime'])))

        partoutput['BasePointsAwarded'] = str('%s' % ('0'))
        adminoutput['BasePointsAwarded'] = str('%s' % ('0'))

        partoutput['SpeedBonusAwarded'] = str('%s' % ('0'))
        adminoutput['SpeedBonusAwarded'] = str('%s' % ('0'))

        partoutput['Penalty'] = str('%s' % ('0'))
        adminoutput['Penalty'] = str('%s' % ('0'))

        partoutput['EulaDateAccepted'] = str('%s' % (EulaDateAccepted))
        adminoutput['EulaDateAccepted'] = str('%s' % (EulaDateAccepted))

        partoutput['EulaId'] = str('%s' % (EulaId))
        adminoutput['EulaId'] = str('%s' % (EulaId))

        partoutput['EulaName'] = str('%s' % (EulaName))
        adminoutput['EulaName'] = str('%s' % (EulaName))

        partoutput['EulaUsername'] = str('%s' % (EulaUsername))
        adminoutput['EulaUsername'] = str('%s' % (EulaUsername))

        tcode = validatectf.makeTCode(int(time.time()))
        partoutput['tcode'] = str('%s' % (tcode))
        adminoutput['tcode'] = str('%s' % (tcode))

        try:
            vcode = validatectf.makeVCode(VKEY, tcode, partoutput['user'], partoutput['Number'], partoutput['Result'], partoutput['BasePointsAwarded'], partoutput['SpeedBonusAwarded'],partoutput['AdditionalBonusAwarded'],partoutput['Penalty'])
            partoutput['vcode'] = str('%s' % (vcode))
            adminoutput['vcode'] = str('%s' % (vcode))
        except:
            logger_admin.exception(str('Exception raised in makeVCode'))

        adminoutputlist = []
        partoutputlist = []
        partoutputlisturl = []

        for k,v in list(adminoutput.items()):
            v.replace(',', '')
            adminoutputlist.append(str('%s=%s' % (k,v)))

        for k,v in list(partoutput.items()):
            v.replace(',', '')
            partoutputlist.append(str('%s=%s' % (k,v)))
            partoutputlisturl.append(str('%s=%s' % (k,urllib.parse.quote(v.encode('utf8')))))

        logger.info(','.join(partoutputlist))
        logger_admin.info(','.join(adminoutputlist))

        raise cherrypy.HTTPRedirect(str('%s?%s' % ('/en-US/app/SA-ctf_scoreboard/result', '&'.join(partoutputlisturl))), 302)

    def get_kv_lookup(self, lookup_file, namespace='lookup_editor', owner=None):
        '''
        Get the contents of a KV store lookup.
        '''

        try:

            if owner is None:
                owner = 'nobody'

            # Get the session key
            session_key = cherrypy.session.get('sessionKey')

            # Get the contents
            _, content = splunk.rest.simpleRequest('/servicesNS/' + owner + '/' + namespace + '/storage/collections/data/' + lookup_file, sessionKey=session_key, getargs={'output_mode': 'json'})

            return content

        except:
            logger_admin.error('KV store lookup could not be loaded')

    def represents_int(self, s):
        try:
            int(s)
            return True
        except ValueError:
            return False
