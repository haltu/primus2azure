import sys
import unittest
import requests
import os
from mock import Mock, patch

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from dataparser import Parser
from config import Config

class ParserTestCase(unittest.TestCase):

  def setUp(self):
    self.parser = Parser()

  def test_required_attribute_keys(self):
    actual_data = {}
    for i in self.parser.parse(Config().get('input', 'input_file')):
      actual_data = i
      break
    
    self.assertTrue(actual_data['attributes']['immutableid'])
    self.assertTrue(actual_data['attributes']['mailnickname'])
    self.assertTrue(actual_data['attributes']['displayname'])
    self.assertTrue(actual_data['attributes']['userprincipalname'])

  def test_parser_output_for_users(self):
    excepted_data = {'licenses': ['STANDARDWOFFPACK_FACULTY'],'attributes': { 'immutableid': 'testi_0022', 'mailnickname': '2erkki.Esimerkki', 'surname': 'Esimerkki', 'facsimiletelephonenumber': 'hexhexhex', 'displayname': '2erkki', 'givenname': '2erkki', 'userprincipalname': '2erkki.Esimerkki@tieraedu.onmicrosoft.com' }, 'groups': ['Edison_Role_Teachers', 'Edison_School_Testikoulu', { 'parent': 'Edison_School_Testikoulu', 'child': 'Edison_School_1B' }]} 
    actual_data = {}
    for i in self.parser.parse(Config().get('input', 'input_file')):
      actual_data = i
      break

    self.assertDictEqual(actual_data, excepted_data)

  def test_parser_output_for_coures(self):
    excepted_data = {'course_name': 'Edison Kurssi Testi 1.0', 'students': ['testi_0021']}
    actual_data = {}
    for i in self.parser.parse_course(Config().get('input', 'course_file')):
      actual_data = i
      break

    self.assertDictEqual(actual_data, excepted_data)


if __name__ == '__main__':
  unittest.main()