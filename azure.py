
# -*- coding: utf-8 -*-
#
# Copyright Haltu Oy, info@haltu.fi

#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.

#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.

#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
import json
import requests
import time
import unicodedata
import re
import datetime
import random
import string
from models import User, session_scope
from requests.packages.urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from config import Config
from sqlalchemy.sql import exists
from dataparser import save_password_file, file_created

LOG = logging.getLogger(__name__)
CONFIG = Config()
LOG.setLevel(getattr(logging, CONFIG.get('app', 'loglevel').upper()))

RESPONSE_CODES_OK = (200, 201, 202, 204)
ADD_MEMBER_BAD_REQUEST = 400
REQUEST_THROTTLED_TEMPORARILY = 503

# PasswordPolicies
DISABLE_PASSWORD_EXPIRATION = "DisablePasswordExpiration"
DISABLE_STRONG_PASSWORD = "DisableStrongPassword"

# Throttle exception retry limit
THROTTLE_RETRY_LIMIT = 7

# Required values in group creation
MAIL_ENABLED = False
SECURITY_ENABLED = True

class AzureError(Exception):
  pass


class ExpiredTokenError(AzureError):
  pass


class AzureAPI(object):

  def __init__(self, domain, client_id, client_secret):
    """
    :auth: an auth dict with client_id, client_secret and domain
    """
    self.token = None
    self.auth = {'client_id': client_id, 'client_secret': client_secret, 'domain': domain}

    # Azure API requires 'a few minutes' to be waited in case of throttle exception.
    # Value in seconds
    self.request_throttled_interval = 300

    # Amount of retries completed
    self.throttle_retries = 0

    self.graph_url = CONFIG.get('azure', 'GRAPH_ENDPOINT')%self.auth['domain']

    self.headers = {}
    
    # List of all groups fetched from Azure
    self.azure_group_list = {}

    # List of all licenses fetched from Azure
    self.azure_license_list = {}

    # List of all users which need to be disabled in Azure once the CSV file has been parsed through
    self.azure_user_list = []
    with session_scope() as session:
      for user in session.query(User).filter(User.is_active==True):
        self.azure_user_list.append(user.immutable_id)

  def generate_headers(self, token):
    auth_token_type, auth_token = token
    headers = {
      'Authorization': "%s %s"%(auth_token_type, auth_token),
      'Accept': 'application/json;odata=minimalmetadata',
      'Content-Type': 'application/json;odata=minimalmetadata',
      'Prefer': 'return-content',
    }
    return headers

  def remove_immutable_attributes(self, data):
    """
    remove any immutable attributes that can not be changed in azure ad from data
    """

    immutables = CONFIG.get('azure', 'immutable_attributes').split(';')
    result = {}
    for key, val in data.iteritems():
      if key not in immutables:
        result[key] = val
    return result

  def translate_attributes(self, data):
    """
    translate a dictionary of attribute data for sending to azure ad
    adds necessary attributes like accountEnabled if they are missing and mangle
    the password into a PasswordProfile.
    """
    attributes = data.copy()
    if 'accountEnabled' not in attributes:
      # by default an enabled account is assumed
      attributes['accountEnabled'] = True
    if 'password' in attributes:
      password_profile = {'password': attributes.get('password', ''), 'forceChangePasswordNextLogin': False}
      password_policies = '%s, %s' % (DISABLE_PASSWORD_EXPIRATION, DISABLE_STRONG_PASSWORD)

      del attributes['password']
      attributes['passwordProfile'] = password_profile
      attributes['passwordPolicies'] = password_policies

    # usageLocation needs to be set in order to add licenses for a user
    attributes['usageLocation'] = CONFIG.get('azure', 'USAGE_LOCATION')

    return attributes

  def make_request(self, method, url, empty_response, **kwargs):
    """
    HTTP Request to Azure Graph API.

    :empty_response: If True responses with status codes 200 (without response data) and 400 will be
    ignored, because they are expected
    """

    retries = 0
    exc = None
    LOG.debug('make_request request method: %s, url: %s kwargs: %s' % (method, url, repr(kwargs)))
    while retries <= int(CONFIG.get('azure', 'CONNECTION_RETRY_LIMIT')):
      try:
        response = getattr(requests, method)(url, **kwargs)
        if response.status_code in RESPONSE_CODES_OK:
          if not empty_response:
            try:
              LOG.debug('make_request response: %s' % (response.text))
              return response.json()
            except ValueError:
              raise AzureError('No JSON data in Azure response')
          else:
            LOG.info("Status 2xx with empty response")
            return None
        elif response.status_code == ADD_MEMBER_BAD_REQUEST and empty_response:
          LOG.info("User already added to the group")
          return None
        elif response.status_code == REQUEST_THROTTLED_TEMPORARILY:
          return AzureError('request_throttled')
        else:
          try:
            payload = response.json()
            if 'odata.error' in payload.keys():
              error_code = payload['odata.error'].get('code', 'none')
              error_msg = payload['odata.error'].get('message', {}).get('value', 'none')
              error_values = repr(payload['odata.error'].get('values', 'none'))
              if error_code.lower() == 'authentication_expiredtoken':
                # no retries, token is expired
                return ExpiredTokenError('authentication_expiredtoken')
              else:
                exc = AzureError('AzureAD connection failed with status: %s, error code: %s, message: %s, values %s' % (response.status_code, error_code, error_msg, error_values))
            else:
              exc = AzureError('AzureAD connection failed with status %s. No error code received, payload: %s' % (response.status_code, payload))
          except ValueError:
            exc = AzureError('AzureAD connection failed with status %s' % response.status_code)
      except requests.exceptions.RequestException as e:
        LOG.warning('AzureAD connection failed', exc_info=True)
        exc = e
      retries += 1
      time.sleep(retries * 2)
    if exc:
      raise exc
    raise AzureError('AzureAD connection failed')

  def prepare_request(self, method, url, empty_response=False, **kwargs):
    """
    If request fails either wait few minutes before trying again or generate new oauth token.
    If request is throttled add a minute to the throttle interval. Azure API requires the throttle
    interval to increase in order for the request to succeed with higher probability.
    """

    request_response = self.make_request(method, url, empty_response, **kwargs)

    if request_response and 'message' in request_response:
      if request_response.message == "authentication_expiredtoken":
        self.token = self.get_oauth2_token(self.auth)
        kwargs['headers'] = self.generate_headers(self.token)
        self.throttle_retries = 0
        self.prepare_request(method, url, empty_response, **kwargs)
      if request_response.message == "request_throttled":
        self.throttle_retries += 1
        while self.throttle_retries <= THROTTLE_RETRY_LIMIT:
          time.sleep(self.request_throttled_interval)
          self.request_throttled_interval += 60
          self.prepare_request(method, url, empty_response, **kwargs)
        if self.throttle_retries > THROTTLE_RETRY_LIMIT:
          raise AzureError('Request Throttled')
    else:
      self.throttle_retries = 0
      return request_response

  def get_oauth2_token(self, auth):
    """
    Request oauth2 API token from AzureAD

    :auth: an auth dict with client_id, client_secret and domain
    :returns: a tuple (token_type, access_token)

    """
    data = {}
    data['grant_type'] = 'client_credentials'
    data['client_id'] = auth['client_id']
    data['client_secret'] = auth['client_secret']
    data['resource'] = CONFIG.get('azure', 'GRAPH_URI')
    auth_url = CONFIG.get('azure', 'AUTH_ENDPOINT') % auth['domain']

    try:
      response = requests.post(auth_url, data=data)
    except requests.exceptions.RequestException:
      LOG.error('Connection error while requesting access token from AzureAD.', exc_info=True)
      raise AzureError('Oauth2 token fetch failed')
    try:
      response_payload = response.json()
    except ValueError:
      LOG.error('Azure AD token api did not return json content. response.text: %(response_text)s, status_code: %(response_status_code)s' % {'response_text': response.text, 'response_status_code': response.status_code})
      raise AzureError('Oauth2 token fetch failed')
    if response.status_code != 200:
      LOG.error('Error while requesting access token from AzureAD. error: %(error)s, error_codes: %(codes)s, error_description: %(description)s' % {'error': response_payload.get('error', ''), 'codes': response_payload.get('error_codes', ''), 'description': response_payload.get('error_description', '')})
      raise AzureError('Oauth2 token fetch failed')

    LOG.debug('Got data from %(auth_url)s: %(response)s' % {'auth_url': auth_url, 'response': response_payload})
    return (response_payload['token_type'], response_payload['access_token'])

  def fetch_feed(self, feed, disable_paging=False):
    """
    Fetch a list of directory items from Azure AD graph API

    A generator function, yields lists of items of length GRAPH_API_PAGE_SIZE.
    :feed: the requested feed, for example "users" or "groups" or "groups/1747ad35-dd4c-4115-8604-09b54f89277d/members"

    """

    if self.token is None:
      self.token = self.get_oauth2_token(self.auth)

    headers = self.generate_headers(self.token)

    def get_payload(response):
      try:
        response_payload = response.json()
      except ValueError:
        LOG.error('Azure AD graph api did not return json content',
                  extra={'data': {
                    'response.text': response.text,
                    'status_code': response.status_code,
                  }})
        raise AzureError('Azure AD graph api did not return json content')
      return response_payload

    next_link = "%(feed)s?api-version=%(api_version)s"%{'feed': feed, 'api_version': CONFIG.get('azure', 'GRAPH_API_VERSION')}
    if not disable_paging:
      next_link = next_link + "&$top=%(page_size)s"%{'page_size': CONFIG.get('azure', 'GRAPH_API_PAGE_SIZE')}

    while next_link:
      try:
        response_payload = self.prepare_request('get', '%s/%s'%(self.graph_url.rstrip('/'), next_link), headers=headers)
      except ExpiredTokenError:
        self.token = self.get_oauth2_token(self.auth)
        headers = self.generate_headers(self.token)
        response_payload = self.prepare_request('get', '%s/%s'%(self.graph_url.rstrip('/'), next_link), headers=headers)

      LOG.debug('Data from Graph API', extra={'data': {'response_payload': response_payload}})

      # next page
      next_link = response_payload.get('odata.nextLink', None)
      if next_link:
        next_link = "%(next_link)s&$top=%(page_size)d&api-version=%(api_version)s"%{'next_link': next_link, 'page_size': CONFIG.get('azure', 'GRAPH_API_PAGE_SIZE'), 'api_version': CONFIG.get('azure', 'GRAPH_API_VERSION')}

      if not 'value' in response_payload.keys():
        LOG.warning('Azure AD response did not have a value', extra={'data': {'response': response_payload}})
        yield (response_payload,)
      else:
        LOG.debug('feed page', extra={'data': {'page': response_payload['value']}})
        yield response_payload['value']
    return

  def get_membership(self, feed):
    if self.token is None:
      self.token = self.get_oauth2_token(self.auth)
    headers = self.generate_headers(self.token)
    url = "%(feed)s?api-version=%(api_version)s"%{'feed': feed + '/getMemberGroups', 'api_version': CONFIG.get('azure', 'GRAPH_API_VERSION')}
    data = json.dumps({'securityEnabledOnly': False})
    response_payload = self.prepare_request('post', '%s/%s'%(self.graph_url.rstrip('/'), url), headers=headers, data=data)

    LOG.debug('Data from Graph API', extra={'data': {'response_payload': response_payload}})

    if not 'value' in response_payload.keys():
      LOG.warning('Azure AD response did not have a value', extra={'data': {'response': response_payload}})
      return (response_payload,)
    else:
      LOG.debug('feed page', extra={'data': {'page': response_payload['value']}})
      return response_payload['value']
    return

  def create_user(self, data):

    password_generated = False

    # If password was not configured, generate a password
    if 'password' not in data['attributes']:
      data['attributes']['password'] = self.generate_password()
      password_generated = True

    attributes = self.translate_attributes(data['attributes'])

    if self.token is None:
      self.token = self.get_oauth2_token(self.auth)
    headers = self.generate_headers(self.token)
    url = "users?api-version=%(api_version)s" % {'api_version': CONFIG.get('azure', 'GRAPH_API_VERSION')}
    response_payload = self.prepare_request('post', '%s/%s' % (self.graph_url.rstrip('/'), url), headers=headers, data=json.dumps(attributes))
    LOG.debug('Data from Graph API', extra={'data': {'response_payload': response_payload}})

    if password_generated:
      save_password_file(attributes['givenname'], attributes['surname'], attributes['userprincipalname'], data['attributes']['password'], file_created)
    
    return response_payload

  def update_user(self, data, create=False):
    """
    Update user account with supplied data
    Create missing account if create=True
    return updated/created user or raise AzureError
    """

    attributes = self.translate_attributes(data['attributes'])
    groups = data['groups']
    licenses = data['licenses']

    if 'immutableid' in attributes:
      immutable_id = attributes['immutableid']
      del attributes['immutableid']
    else:
      user = attributes.get('userPrincipalName', repr(data))
      raise AzureError('Invalid data for user. Missing immutableId. User: %s'%user)

    if self.token is None:
      self.token = self.get_oauth2_token(self.auth)
    headers = self.generate_headers(self.token)

    # Splits userprincipalname using @ as the separator to check if the email address 
    # includes the allowed domain string. This prevents situations where user name might
    # include part of the whitelisted domain
    if CONFIG.get('azure', 'ALLOWED_DOMAIN'):
      user_principal_name_split = attributes.get('userprincipalname').split('@')      
      if CONFIG.get('azure', 'ALLOWED_DOMAIN') not in user_principal_name_split[1]:
        return None

    # get listing of users with this immutableId
    url = "%(feed)s?api-version=%(api_version)s&$filter=immutableId eq '%(immutableId)s'"%{'feed': 'users', 'immutableId': immutable_id, 'api_version': CONFIG.get('azure', 'GRAPH_API_VERSION')}
    response_payload = self.prepare_request('get', '%s/%s' % (self.graph_url.rstrip('/'), url), headers=headers)
    if not 'value' in response_payload:
      raise AzureError('Invalid response from Azure: %s' % repr(response_payload))
    users = response_payload['value']
    if len(users) == 0:
      # no users found with this immutableId. create new or bail out.
      if create:
        response_payload = self.create_user(data)
        self.add_user_to_db(immutable_id, response_payload['objectId'], True)
        self.get_member_groups(response_payload['objectId'], groups, headers)
        self.get_or_create_groups(response_payload['objectId'], groups, response_payload, headers)
        self.get_or_create_licenses(licenses, response_payload['objectId'], headers)
        return response_payload
      else:
        raise AzureError('User does not exist: %s' % repr(data))
    if len(users) > 1:
      raise AzureError('Multiple users with immutableId %s in Azure! Data must be fixed.')

    # found exactly one user with this immutableId. update it.
    azure_user = users[0]
    LOG.debug('update_user: Found Azure user %s' % repr(azure_user))
    url = "%(feed)s?api-version=%(api_version)s" % {'feed': 'users/%s' % azure_user['objectId'], 'api_version': CONFIG.get('azure', 'GRAPH_API_VERSION')}
    update_data = self.remove_immutable_attributes(attributes)

    if 'passwordProfile' in update_data:
      del update_data['passwordProfile']

    response_payload = self.prepare_request('patch', '%s/%s' % (self.graph_url.rstrip('/'), url), headers=headers, data=json.dumps(update_data))
    LOG.debug('update_user: Update result: %s', repr(response_payload))
    user_id = response_payload['objectId']

    # If database has been cleared, users will be added back into the database 
    if (self.user_exists(immutable_id)):
      self.update_user_in_db(immutable_id)
      self.azure_user_list.remove(immutable_id)      
    else:
      self.add_user_to_db(immutable_id, response_payload['objectId'], True)

    self.get_member_groups(user_id, groups, headers)
    self.get_or_create_groups(user_id, groups, response_payload, headers)
    self.get_or_create_licenses(licenses, user_id, headers)

    return response_payload

  def create_course(self, input_data):
    """
    Add students to a course. If a student's immutableid is not found on the local database,
    a warning is displayed prompting the user to add the student manually.
    """

    for student in input_data['students']:
      azure_id = self.get_azure_id(student)
      if azure_id:
        self.get_or_create_groups(azure_id[0], [ input_data['course_name'] ], None, self.generate_headers(self.token))
      else:
        LOG.warning("User does not exist and needs to be created manually. id: %s" % student)

  def get_member_groups(self, user_id, groups, headers):
    """
    Fetch groups the user is a member of in order to get IDs of the groups.
    """

    url = "%(feed)s/%(user_id)s/%(path)s?api-version=%(api_version)s" % {'feed': 'users', 'api_version': CONFIG.get('azure', 'GRAPH_API_VERSION'), 'user_id': user_id, 'path': 'memberOf'}
    response_payload = self.prepare_request('get', '%s/%s' % (self.graph_url.rstrip('/'), url), headers=headers)
    LOG.debug('get_member_groups: Get groups: %s', repr(response_payload))
    self.remove_user_from_group(user_id, groups, response_payload, headers)

  def remove_user_from_group(self, user_id, groups, response, headers):
    """
    Compare groups the user is currently a member of and groups the user is about to be added to.
    If a group cannot be found from the new groups. User will be removed from the group they are
    still member of.
    
    :response: Group DirectoryObjects
    """
    
    old_groups = {}
    response_arr = response['value']
    for response in response_arr:
      old_groups[response['displayName']] = response['objectId']

    new_groups = list(groups)
    for temp in new_groups:
      if 'child' in temp:
        new_groups.append(temp['child'])

    for group in old_groups.keys():
      if group not in new_groups:
        url = "%(feed)s/%(group_id)s/%(path)s/%(user_id)s?api-version=%(api_version)s" % {'feed': 'groups', 'api_version': CONFIG.get('azure', 'GRAPH_API_VERSION'), 'group_id': old_groups[group], 'path': '$links/members', 'user_id': user_id}
        response_payload = self.prepare_request('delete', '%s/%s' % (self.graph_url.rstrip('/'), url), headers=headers, empty_response=True)
        LOG.info('remove_user_from_group: Remove user from group: %s', repr(response_payload))

  def get_or_create_groups(self, user_id, groups, response_payload, headers):
    """
    Check if a group already exists in Azure by fetching all the groups during the first user
    iteration. After that check whether a group exists from the cached list of azure groups. If the
    group does not exist create it. Add user to the group that was created or fetched.
    """

    # Fetch groups if they haven't been fetched yet
    if len(self.azure_group_list) == 0: 
      paging = self.fetch_feed('groups')
      # Add user to groups which were found
      for group_response in paging:
        for group in group_response:
          self.azure_group_list[group['displayName']] = group['objectId']
          if group['displayName'] in groups:
            self.add_user_to_group(group['objectId'], user_id, headers)
            groups.remove(group['displayName'])
          # Save parent and child group ids in order to only create the groups that have no ids
          for g in groups:
            if 'parent' in g:
              if group['displayName'] == g['child']:
                g['child_id'] = group['objectId']
              elif group['displayName'] == g['parent']:
                g['parent_id'] = group['objectId']
    else:
      remove_groups = []
      for group in groups:
        if group in self.azure_group_list.keys():
          self.add_user_to_group(self.azure_group_list[group], user_id, headers)
          remove_groups.append(group)

        if 'parent' in group:
          if group['parent'] in self.azure_group_list.keys():
            group['parent_id'] = self.azure_group_list[group['parent']]
          if group['child'] in self.azure_group_list.keys():
            group['child_id'] = self.azure_group_list[group['child']]

      # Remove groups which user has already been added to 
      for group in remove_groups:
        if 'parent' in group:
          if group['parent'] in groups:
            groups.remove(group['parent'])
          elif group['child'] in groups:
            groups.remove(group['child'])
        else:
          if group in groups:
            groups.remove(group)

    # Create groups which were not found and add user to the group
    for group in groups:
      # Check for dict in list
      if 'parent' in group:
        # Check if the groups need to be created
        if 'child_id' not in group:
          if group['child'] in self.azure_group_list.keys():
            group['child_id'] = self.azure_group_list[group['child']]
          else:
            group_response = self.create_group(group['child'], headers)
            group['child_id'] = group_response['objectId']
        if 'parent_id' not in group:
          if group['parent'] in self.azure_group_list.keys():
            group['parent_id'] = self.azure_group_list[group['parent']]
          else:
            group_response = self.create_group(group['parent'], headers)
            group['parent_id'] = group_response['objectId']
        # Add user to child group and add child group to parent group
        self.add_user_to_group(group['parent_id'], group['child_id'], headers)
        self.add_user_to_group(group['child_id'], user_id, headers)
      else:
        if group not in self.azure_group_list.keys():
          group_response = self.create_group(group, headers)
          self.add_user_to_group(group_response['objectId'], user_id, headers)
        else:
          self.add_user_to_group(self.azure_group_list[group], user_id, headers)

  def get_or_create_licenses(self, licenses, user_id, headers):
    """
    Fetch all licenses on the first iteration, save the name and ID to a list and use the list
    to lookup the IDs with the following iterations.
    """

    if len(self.azure_license_list) == 0: 
      # Fetch and add licenses
      license_response = self.get_licenses(headers)
      for license in license_response['value']:
        self.azure_license_list[license['skuPartNumber']] = license['skuId']
               
        if license['skuPartNumber'] in licenses:
          self.add_license(license['skuId'], user_id, headers)
    else:
      for license in licenses:
        if license in self.azure_license_list.keys():
          self.add_license(self.azure_license_list[license], user_id, headers)

  def generate_user_url(self, user_id):
    """
    Return a user specific url
    """  

    return "%(url)s/%(feed)s/%(user_id)s" % {'url': self.graph_url.rstrip('/'), 'feed': 'directoryObjects', 'user_id': user_id}

  def create_group(self, group_name, headers):
    url = "%(feed)s?api-version=%(api_version)s" % {'feed': 'groups', 'api_version': CONFIG.get('azure', 'GRAPH_API_VERSION')}
    post_data = { 'displayName': group_name, 'mailEnabled': MAIL_ENABLED, 'mailNickname': self.slugify(group_name), 'securityEnabled': SECURITY_ENABLED }
    response_payload = self.prepare_request('post', '%s/%s' % (self.graph_url.rstrip('/'), url), headers=headers, data=json.dumps(post_data))
    LOG.debug('create_group: Create group: %s', repr(response_payload))
    self.azure_group_list[response_payload['displayName']] = response_payload['objectId']
    return response_payload

  def add_user_to_group(self, group_id, user_id, headers):
    """
    :group_id: ID of the group which the user will be added to
    :user_id: ID of the user or group which will be added to the group specified with the group_id
    """

    url = "%(feed)s/%(group_id)s/%(path)s?api-version=%(api_version)s" % {'feed': 'groups', 'api_version': CONFIG.get('azure', 'GRAPH_API_VERSION'), 'group_id': group_id, 'path': '$links/members'}
    post_data = { 'url': self.generate_user_url(user_id) }
    response_payload = self.prepare_request('post', '%s/%s' % (self.graph_url.rstrip('/'), url), headers=headers, data=json.dumps(post_data), empty_response=True)
    LOG.debug('add_user_to_group: Add user: %s', repr(response_payload))

  def slugify(self, value):
    """
    Return a camelcased value without whitespaces
    e.g. Tampereen koulu -> TampereenKoulu
    """

    value = unicode(value, 'utf-8')
    value = unicodedata.normalize('NFKD', value).encode('ascii', 'ignore').decode('ascii')
    value = re.sub('[^\w\s-]', '', value.title()).strip()
    return re.sub('[\s]+', '', value)

  def add_license(self, license_id, user_id, headers):
    url = "%(feed)s/%(user_id)s/%(path)s?api-version=%(api_version)s" % {'feed': 'users', 'api_version': CONFIG.get('azure', 'GRAPH_API_VERSION'), 'user_id': user_id, 'path': 'assignLicense'}
    post_data = { 'addLicenses': [{ 'disabledPlans': [], 'skuId': license_id }], 'removeLicenses': [] }
    response_payload = self.prepare_request('post', '%s/%s' % (self.graph_url.rstrip('/'), url), headers=headers, data=json.dumps(post_data))
    LOG.debug('add_license: Add License: %s', repr(response_payload))
    return response_payload

  def get_licenses(self, headers):
    url = "%(feed)s?api-version=%(api_version)s" % {'feed': 'subscribedSkus', 'api_version': CONFIG.get('azure', 'GRAPH_API_VERSION')}
    response_payload = self.prepare_request('get', '%s/%s' % (self.graph_url.rstrip('/'), url), headers=headers)
    LOG.debug('get_licenses: Get Licenses: %s', repr(response_payload))    
    return response_payload

  def user_exists(self, immutable_id):
    """
    Returns True if user exists in the database
    """
    with session_scope() as session:
      user_filter = exists().where(User.immutable_id==immutable_id)
      for user in session.query(User.immutable_id).filter(user_filter):
        if user:
          return True
        else:
          return False

  def update_user_in_db(self, immutable_id):
    """
    Updates the synced time with the current time 
    """

    with session_scope() as session:
      user = session.query(User).filter_by(immutable_id=immutable_id).first()
      if user:
        user.synced = datetime.datetime.now()
        session.add(user)

  def user_exists(self, immutable_id):
    with session_scope() as session:
      user = session.query(User).filter_by(immutable_id=immutable_id).first()

      if user:
        return True
      else:
        return False

  def add_user_to_db(self, immutable_id, user_id, is_active):
    user = User()
    user.immutable_id = immutable_id
    user.azure_user_id = user_id
    user.is_active = is_active
    user.created = datetime.datetime.now()
    user.synced = datetime.datetime.now()
    with session_scope() as session:
      session.add(user)

  def is_active(self, immutable_id):
    with session_scope() as session:
      for active in session.query(User.is_active).filter(User.immutable_id==immutable_id):
        return active

  def remove_user_from_db(self, immutable_id):
    with session_scope() as session:
      user = session.query(User).filter_by(immutable_id=immutable_id).first()
      session.delete(user)

  def get_azure_id(self, immutable_id):
    """
    Return Azure User ID, None is returned if a user with given ID is not found. 
    """
    with session_scope() as session:
      azure_id = session.query(User.azure_user_id).filter_by(immutable_id=immutable_id).first()
      return azure_id

  def delete_users(self):
    """
    Delete all the users that were not found on the CSV file but were still present in the database.
    """

    for user in self.azure_user_list:
      with session_scope() as session:
        user = session.query(User).filter_by(immutable_id=user).first()
        self.remove_user_from_db(user.immutable_id)
        self.delete_user(user.azure_user_id)

  def delete_user(self, user_id):
    """
    Delete user from Azure.
    """

    url = "%(feed)s?api-version=%(api_version)s" % {'feed': 'users/%s' % user_id, 'api_version': CONFIG.get('azure', 'GRAPH_API_VERSION')}
    response_payload = self.prepare_request('delete', '%s/%s' % (self.graph_url.rstrip('/'), url), headers=self.generate_headers(self.token), empty_response=True)
    LOG.debug('delete_user, DELETE: %s', repr(response_payload))

  def generate_password(self, length=8):
    """
    Generate a randomized password containing uppercase and lowercase letters as well as numbers.
    """
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(length))

# vim: tabstop=2 expandtab shiftwidth=2 softtabstop=2

