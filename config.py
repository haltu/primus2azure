
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

import os
import sys
import logging
from ConfigParser import RawConfigParser

LOG = logging.getLogger(__name__)
logging.basicConfig()
DEFAULT_CONFIG_FILE_NAME = 'defaults.cfg'
CONFIG_FILE_NAME = 'primus2azure.cfg'

if getattr(sys, 'frozen', False):
  # The application is frozen
  BASEDIR = os.path.dirname(sys.executable)
else:
  BASEDIR = os.path.dirname(os.path.abspath(__file__))

CONFIG_SECTION_INPUT = 'input'
CONFIG_SECTION_RULES = 'rules'
CONFIG_SECTION_GROUPS = 'groups'
CONFIG_SECTION_LICENSES = 'licenses'


class ConfigurationError(Exception):
  pass


class Config:
  """
  Config stores the configuration and reads it from a file.
  It's class with shared state across all instances (the Borg pattern)
  """
  __shared_state = {}

  def __init__(self):
    self.__dict__ = self.__shared_state
    self.config = None

  def read_config_file(self, config_file=os.path.join(BASEDIR, CONFIG_FILE_NAME)):
    self.config = RawConfigParser()
    try:
      self.config.readfp(open(os.path.join(BASEDIR, DEFAULT_CONFIG_FILE_NAME), 'r'))
      self.config.readfp(open(config_file, 'r'))
    except (OSError, IOError):
      LOG.exception('Could not open configuration file')
      raise ConfigurationError('Could not open configuration file')

  def get(self, section, option):
    if self.config is None:
      self.read_config_file()
    return self.config.get(section, option)

  def items(self, section):
    if self.config is None:
      self.read_config_file()
    return self.config.items(section)

# vim: tabstop=2 expandtab shiftwidth=2 softtabstop=2

