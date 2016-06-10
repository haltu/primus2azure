import sys
import unittest
import requests
import os
import datetime
from mock import Mock, patch

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from azure import AzureAPI
from config import Config
import models

class ModelsTestCase(unittest.TestCase):

  def setUp(self):
    pass

  def tearDown(self):
    pass

if __name__ == '__main__':
  unittest.main()