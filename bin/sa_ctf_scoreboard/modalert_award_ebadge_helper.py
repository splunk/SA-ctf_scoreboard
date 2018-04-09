
# encoding = utf-8

import logging
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
import splunk.rest
import json
import collections
import urllib

def process_event(helper, *args, **kwargs):
    
    logger = setup_logger(logging.INFO, 'scoreboard.log')
    logger_admin = setup_logger(logging.INFO, 'scoreboard_admin.log')

    users_string = get_kv_lookup(helper, 'ctf_users', logger_admin, 'SA-ctf_scoreboard', 'nobody')
    badges_string = get_kv_lookup(helper, 'ctf_badges', logger_admin, 'SA-ctf_scoreboard', 'nobody')
    badge_entitlements_string = get_kv_lookup(helper, 'ctf_badge_entitlements', logger_admin, 'SA-ctf_scoreboard', 'nobody')
    
    users = json.loads(users_string)
    badges = json.loads(badges_string)
    badge_entitlements = json.loads(badge_entitlements_string)

    users_by_Username = dict()
    users_by_Team = dict()

    for user_entry in users:
        users_by_Username[user_entry['Username']] = user_entry
        if 'Team' in user_entry:
            if user_entry['Team'] != '':
                if user_entry['Team'] not in users_by_Team:
                    users_by_Team[user_entry['Team']] = []
                users_by_Team[user_entry['Team']].append(user_entry['Username'])

    recipient = helper.get_param('recipient')
    unstripped_recipient_list = recipient.split(',')
    recipient_list = [item.strip() for item in unstripped_recipient_list]

    ebadge = helper.get_param('ebadge')

    notes = helper.get_param('notes')
    notes = notes.replace('"', "'")

    award_to_entire_team = helper.get_param('award_to_entire_team').strip().lower()
    if award_to_entire_team == 'true' or award_to_entire_team == '1':
        award_to_entire_team = '1'

    expanded_recipients = set()
    for r in recipient_list:
        if r in users_by_Username or r in users_by_Team:
            expanded_recipients.add(r)
            if r in users_by_Username and award_to_entire_team == '1':
                expanded_recipients.add(users_by_Username[r]['Team'])

    actual_recipients = set()
    for er in expanded_recipients:
        if er in users_by_Username:
            actual_recipients.add(er)
        if er in users_by_Team:
            for t in users_by_Team:
                if t == er:
                    for u in users_by_Team[t]:
                        actual_recipients.add(u)

    for a in actual_recipients:


        badge_exists = False
        for eb_dict in badges:
            if eb_dict['BadgeNumber'] == ebadge:
                badge_exists = True

        badge_already_awarded = False
        for eb_entitlement_dict in badge_entitlements:
            if eb_entitlement_dict['BadgeNumber'] == ebadge and eb_entitlement_dict['user'] == a:
                badge_already_awarded = True

        if badge_exists and not badge_already_awarded:
            response = '0'
            try:
                uri = '/servicesNS/' + 'nobody' + '/' + 'SA-ctf_scoreboard' + '/storage/collections/data/' + 'ctf_badge_entitlements'
                payload = {
                   'BadgeNumber': ebadge,
                   'user' : a
                }
                payload_json = json.dumps(payload)

                response, content = splunk.rest.simpleRequest(uri, method='POST', jsonargs=payload_json, sessionKey=helper.session_key)

            except:
                logger_admin.exception('Error posting update the ctf_badge_entitlements lookup.')

        adminoutput = collections.OrderedDict()
        partoutput = collections.OrderedDict() 

        adminoutput['Result'] = unicode('%s' % ('Badge'))
        partoutput['Result'] = unicode('%s' % ('Badge'))

        if badge_already_awarded:
            adminoutput['BadgeAlreadyAwarded'] = unicode('%s' % ('1'))
            partoutput['BadgeAlreadyAwarded'] = unicode('%s' % ('1'))

        if not badge_exists:
            adminoutput['BadgeNumberNotFound'] = unicode('%s' % ('1'))
            partoutput['BadgeNumberNotFound'] = unicode('%s' % ('1'))

        adminoutput['user'] = unicode('%s' % (a))
        partoutput['user'] = unicode('%s' % (a))

        adminoutput['BadgeNumber'] = unicode('%s' % (ebadge))
        partoutput['BadgeNumber'] = unicode('%s' % (ebadge))

        adminoutput['Notes'] = unicode('"%s"' % (notes))
        partoutput['Notes'] = unicode('"%s"' % (notes))

        adminoutput['AwardToEntireTeam'] = unicode('%s' % (award_to_entire_team))
        partoutput['AwardToEntireTeam'] = unicode('%s' % (award_to_entire_team))

        adminoutputlist = []
        partoutputlist = []
        partoutputlisturl = []

        for k,v in adminoutput.items():
            v.replace(',', '')
            adminoutputlist.append(unicode('%s=%s' % (k,v)))

        for k,v in partoutput.items():
            v.replace(',', '')
            partoutputlist.append(unicode('%s=%s' % (k,v)))
            partoutputlisturl.append(unicode('%s=%s' % (k,urllib.quote(v))))

        logger.info(','.join(partoutputlist))
        logger_admin.info(','.join(adminoutputlist))

    return 0

def setup_logger(level, filename):
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

def get_kv_lookup(self, lookup_file, logger_admin, namespace='lookup_editor', owner=None):
    '''
    Get the contents of a KV store lookup.
    '''
    try:
        if owner is None:
            owner = 'nobody'
        # Get the contents
        _, content = splunk.rest.simpleRequest('/servicesNS/' + owner + '/' + namespace + '/storage/collections/data/' + lookup_file, sessionKey=self.session_key, getargs={'output_mode': 'json'})
        return content
    except:
        logger_admin.error('KV store lookup could not be loaded')
