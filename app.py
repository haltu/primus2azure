
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

import sys
import os
import logging
from dataparser import Parser
from azure import AzureAPI
from config import Config

CONFIG = Config()
logging.basicConfig(level=getattr(logging, CONFIG.get('app', 'loglevel').upper()))
LOG = logging.getLogger(__name__)

parser = Parser()
azure = AzureAPI(CONFIG.get('azure', 'domain'), CONFIG.get('azure', 'client_id'), CONFIG.get('azure', 'client_secret'))

# if the app is frozen using cx_freeze, we need to tell requests where to find
# the certificate bundle
if getattr(sys, 'frozen', False):
  # The application is frozen
  os.environ["REQUESTS_CA_BUNDLE"] = os.path.join(os.path.dirname(sys.executable), "cacert.pem")

for u in parser.parse(CONFIG.get('input', 'input_file')):
  try:
    azure.update_user(u, create=True)
  except:
    LOG.error('update_user failed', exc_info=True)

# Parse course file if it exists
if os.path.isfile(CONFIG.get('input', 'course_file')):
  for course in parser.parse_course(CONFIG.get('input', 'course_file')):
    try:
      azure.create_course(course)
    except:
      LOG.error('create_course failed', exc_info=True)

# After all data has been parsed, delete users
azure.delete_users()
