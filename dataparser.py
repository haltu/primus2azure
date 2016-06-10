
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

import csv
import shlex
import logging
import operator
import random
import string
import datetime
import time
import os
from os import path
from config import Config, CONFIG_SECTION_INPUT, CONFIG_SECTION_RULES, CONFIG_SECTION_GROUPS, CONFIG_SECTION_LICENSES

LOG = logging.getLogger(__name__)
logging.basicConfig()
CONFIG = Config()

CSV_DELIMITER = ';'
COURSE_FILE_STUDENT_DELIMITER = ','
PASSWORD_OUTPUT_FILENAME = "Primus2Azure-Password-File"

file_created = False

def save_password_file(givenname, surname, email, password, file_created):
  """
  Create a file containing the name and email of the user and a randomly generated password. 

  If the filename is not found, generate it by adding date to a predetermined filename. If the
  filename is set, file already exists and data should be appended to the file. 
  """
  
  # Generate file name appending date to the filename
  if not file_created:
    today = datetime.datetime.today()
    output_file = "%s-%s_%s_%s" % (PASSWORD_OUTPUT_FILENAME, str(today.day), str(today.month), str(today.year))
    file_created = True

  file_path = CONFIG.get('azure', 'PASSWORD_FILE_LOCATION').replace('base_dir/', '')
    
  # If backslash is not the last character append it to the path string in order for the path
  # to be created 
  if file_path and not file_path[:-1] == '/':
    file_path += "/"
    
  # Create path if necessary
  if file_path and not os.path.exists(file_path):
      os.makedirs(file_path)

  file_dir = os.path.dirname(os.path.abspath(__file__))
  filename = os.path.join(file_dir, file_path + output_file)
  with open(filename, 'a') as output:
    output.write("%s %s (%s) - Password: %s\n" % (givenname, surname, email, password))    

class ParserError(Exception):
  pass


class AttributeRule(object):
  """
  Represents a mapping of one attribute in input data to output data

  Parser creates an AttributeRule for each attribute rule in the configuration.
  When parsing data, the input row is fed to each AttributeRule, forming the
  data which is passed to AzureAD.

  An AttributeRule can be conditional, generating output only if the condition
  is true.
  """
  def __init__(self, attribute_name, attribute_template, condition_operator=None, condition_field=None, condition_value=None, *args, **kwargs):
    self.attribute_name = attribute_name
    self.attribute_template = attribute_template
    self.condition_operator = condition_operator
    self.condition_field = condition_field
    self.condition_value = condition_value

  def transform(self, data):
    if self.condition_operator and self.condition_field and self.condition_value:
      if not self.condition_operator(data.get(self.condition_field), self.condition_value):
        return {}
    try:
      output = {self.attribute_name: self.attribute_template.format(**data)}
    except KeyError:
      LOG.warning('No data for rule %s: %s' % (self.attribute_name, self.attribute_template))
      output = {}
    return output

class GroupRule(object):
  """
  Represents a mapping of one attribute in input data to output data

  Supports IF statements and hierarchical groups with MEMBEROF statement.
  """
  # opettaja = [groupinnimi] MEMBEROF [toinengrouppi] IF role = opettaja

  def __init__(self, group_name, group_template, group_template_parent=None, condition_operator=None, condition_field=None, condition_value=None, *args, **kwargs):
    self.group_name = group_name
    self.group_template = group_template
    self.group_template_parent = group_template_parent
    self.condition_operator = condition_operator
    self.condition_field = condition_field
    self.condition_value = condition_value

  def transform(self, data):

    if self.condition_operator and self.condition_field and self.condition_value:
      if not self.condition_operator(data.get(self.condition_field), self.condition_value):
        return None
    try:
      output = []
      # If group is a memberof another, return them both as a dict
      if self.group_template_parent:
        output.append({'parent': self.group_template_parent.format(**data), 'child': self.group_template.format(**data)})
      else:
        output.append(self.group_template.format(**data))
    except KeyError:
      LOG.warning('error')

    return output

class LicenseRule(object):
  """
  Represents a mapping of one attribute in input data to output data

  Supports IF statements
  """
  
  def __init__(self, license_name, license_template, condition_operator=None, condition_field=None, condition_value=None, *args, **kwargs):
    self.license_name = license_name
    self.license_template = license_template
    self.condition_operator = condition_operator
    self.condition_field = condition_field
    self.condition_value = condition_value
    
  def transform(self, data):
    if self.condition_operator and self.condition_field and self.condition_value:
      if not self.condition_operator(data.get(self.condition_field), self.condition_value):
        return None
    try:
      output = self.license_template.format(**data)
    except KeyError:
      LOG.warning('LicenseRule error')

    return output

class Parser(object):
  def __init__(self, *args, **kwargs):
    self.attribute_rules = self.create_attribute_rules(CONFIG.items(CONFIG_SECTION_RULES))
    self.group_rules = self.create_group_rules(CONFIG.items(CONFIG_SECTION_GROUPS))
    self.license_rules = self.create_lincense_rules(CONFIG.items(CONFIG_SECTION_LICENSES))
    
    # Caches the file name in order to prevent new file from being created if day changes while the
    # script is still running 
    self.password_output_file = ""

  def parse_attribute_rule(self, rule):
    # rule: {class} IF role = "oppilas"
    # tokens: ['{class}', 'IF', 'role', '=', 'oppilas']
    tokens = shlex.split(rule)
    if "IF" in tokens:
      # conditional rule
      return {
        'attribute_template': tokens[0],
        'condition_operator': self.select_operator(tokens[3]),
        'condition_field': tokens[2],
        'condition_value': tokens[4],
      }
    else:
      return {
        'attribute_template': tokens[0]
      }

  def parse_group_rule(self, rule):

    tokens = shlex.split(rule)
    # example: opettaja = [group1] MEMBEROF [group2] IF role = opettaja
    # tokens: ['[group1]', 'MEMBEROF', '[group2]', 'IF', 'role', '=', 'opettaja']
    if "MEMBEROF" in tokens:
      if "IF" in tokens:
        return {
          'group_template': tokens[0],
          'group_template_parent': tokens[2],
          'condition_operator': self.select_operator(tokens[5]),
          'condition_field': tokens[4],
          'condition_value': tokens[6]
        }
      else:
        return {
          'group_template': tokens[0],
          'group_template_parent': tokens[2],
        }
    elif "IF" in tokens:
      return {
        'group_template': tokens[0],
        'condition_operator': self.select_operator(tokens[3]),
        'condition_field': tokens[2],
        'condition_value': tokens[4]
      }
    else:
      return {
        # PARSI KOULU INFO
        'group_template': tokens[0]
      }

    return None

  def parse_license_rule(self, rule):
    tokens = shlex.split(rule)
    if "IF" in tokens:
      return {
        'license_template': tokens[0],
        'condition_operator': self.select_operator(tokens[3]),
        'condition_field': tokens[2],
        'condition_value': tokens[4]
      }
    else:
      return {
        'license_template': tokens[0]
      }

  def select_operator(self, op_str):
    if op_str == '=':
      return operator.eq
    elif op_str == '!=':
      return operator.ne
    elif op_str == 'contains':
      return operator.contains
    else:
      raise ParserError('Invalid operator %s' % op_str)

  def create_attribute_rules(self, rules):
    rule_objs = []
    for name, value in rules:
      rule_objs.append(AttributeRule(name, **self.parse_attribute_rule(value)))
    return rule_objs

  def create_group_rules(self, rules):
    rule_objs = []
    for name, value in rules:
      rule_objs.append(GroupRule(name, **self.parse_group_rule(value)))
    return rule_objs

  def create_lincense_rules(self, rules):
    rule_objs = []
    for name, value in rules:
      rule_objs.append(LicenseRule(name, **self.parse_license_rule(value)))
    return rule_objs

  def parse(self, file_name):
    """
    Parses given input file for data. Headers for the data must be presented
    in the config. Yields dictionaries for each line in the input
    {'attributes': {'attr1': 'val1', 'attr2', 'val2'}, 'groups': []}
    """

    headers = CONFIG.get(CONFIG_SECTION_INPUT, 'headers').split(';')
    with open(file_name, 'rb') as csvfile:
      reader = csv.reader(csvfile, delimiter=CSV_DELIMITER)
      for row in reader:
        if len(row) != len(headers):
          raise ParserError('Number of columns does not match number of headers: %s' % ';'.join(row))
        input_data = dict(zip(headers, row))
        attribute_data = self.transform_attribute_data(input_data)
        group_data = self.transform_group_data(input_data)
        license_data = self.transform_license_data(input_data)

        LOG.debug('attributes: %s' % repr(attribute_data))
        LOG.debug('groups: %s' % repr(group_data))
        LOG.debug('licenses: %s' % repr(license_data))

        yield {'attributes': attribute_data, 'groups': group_data, 'licenses': license_data}

  def parse_course(self, file_name):
    """
    Parses given input file and returns the data as a dictionary containing the course name and list
    of students to be added to the course.
    """
    with open(file_name, 'rb') as csvfile:
      reader = csv.reader(csvfile, delimiter=CSV_DELIMITER)
      for row in reader:
        if len(row) != 2:
          raise ParserError('Course file must include course name and the students')
        yield {'course_name': row[0], 'students': row[1].split(COURSE_FILE_STUDENT_DELIMITER)}


  def transform_attribute_data(self, input_data):
    attributes = {}
    for rule in self.attribute_rules:
      attributes.update(rule.transform(input_data))
    return attributes

  def transform_group_data(self, input_data):
    groups = []
    for rule in self.group_rules:
      # Append group if group was returned
      group = rule.transform(input_data)
      if group:
        groups.extend(group)
    return groups

  def transform_license_data(self, input_data):
    licenses = []
    for rule in self.license_rules:
      license = rule.transform(input_data)
      if license:
        licenses.append(license)
    return licenses

# vim: tabstop=2 expandtab shiftwidth=2 softtabstop=2

