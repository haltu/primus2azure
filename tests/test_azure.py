import sys
import unittest
import requests
import os
import mock
from mock import Mock, patch

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from azure import AzureAPI, save_password_file
from config import Config

class AzureTestCase(unittest.TestCase):

  def setUp(self):
    self.azure = AzureAPI("domain", "client", "secret")
    self.data = {'licenses': ['STANDARDWOFFPACK_FACULTY'],'attributes': { 'immutableid': 'testi_0022', 'mailnickname': '2erkki.Esimerkki', 'surname': 'Esimerkki', 'facsimiletelephonenumber': 'hexhexhex', 'displayname': '2erkki', 'givenname': '2erkki', 'userprincipalname': '2erkki.Esimerkki@tieraedu.onmicrosoft.com' }, 'groups': ['Edison_Role_Teachers', 'Edison_School_Testikoulu', { 'parent': 'Edison_School_Testikoulu', 'child': 'Edison_School_1B' }]}
    self.response_data = {'user ok'}
    self.response_mock = Mock()
    self.response_mock.status_code = requests.codes.ok
    self.response_mock.json.return_value = self.response_data
    self.azure.token = {'foo': 'foo', 'bar': 'bar'}

  def test_user_creation_attributes(self):
    attributes = self.azure.translate_attributes(self.data['attributes'])
    del attributes['immutableid']
    self.data['attributes']['password'] = self.azure.generate_password()
    attributes = self.azure.translate_attributes(self.data['attributes'])

    self.assertTrue(attributes['givenname'])
    self.assertTrue(attributes['surname'])
    self.assertTrue(attributes['userprincipalname'])
    self.assertTrue(attributes['passwordProfile']['password'])

  @patch.object(AzureAPI, 'prepare_request')
  def test_user_creation(self, mock):
    self.azure.create_user(self.data)

  @patch.object(AzureAPI, 'add_user_to_group')
  def test_groups_without_group_fetch(self, mock):
    groups_data = ['group']
    self.azure.azure_group_list['group'] = 'abc123'
    self.azure.get_or_create_groups('123456-123K', groups_data, None, self.azure.generate_headers(self.azure.token))

  @patch.object(AzureAPI, 'add_user_to_group')
  @patch.object(AzureAPI, 'prepare_request')
  def test_groups_with_group_fetch(self, mock_add, mock_prepare):
    groups_data = ['group']
    self.azure.get_or_create_groups('123456-123K', groups_data, None, self.azure.generate_headers(self.azure.token))

  @patch.object(AzureAPI, 'prepare_request')
  def test_remove_user_from_group(self, mock):
    groups_data = ['group']
    response_data = {'value': [{'displayName': 'Test Group', 'objectId': '123abc'}] }
    self.azure.remove_user_from_group('123456-123K', groups_data, response_data, self.azure.generate_headers(self.azure.token))

  def test_make_request_success_with_empty_response(self):
    mock_request = mock.Mock()
    mock_request.POST = { 'displayName': 'Test group', 'mailEnabled': False, 'mailNickname': 'TestGroup', 'securityEnabled': True}
    expected_data = None
    with mock.patch.object(self.azure, 'make_request', return_value=None):
      query_result = self.azure.make_request(request=mock_request)

    self.assertEqual(query_result, expected_data)
    

if __name__ == '__main__':
  unittest.main()