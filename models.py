
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
import datetime
import logging
from contextlib import contextmanager
from sqlalchemy import *
from sqlalchemy.orm import relationship, backref, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from config import Config

CONFIG = Config()
logging.basicConfig(level=getattr(logging, CONFIG.get('app', 'loglevel').upper()))
LOG = logging.getLogger(__name__)

if getattr(sys, 'frozen', False):
  # The application is frozen
  BASEDIR = os.path.dirname(sys.executable)
else:
  BASEDIR = os.path.dirname(os.path.abspath(__file__))

# Initialize local database
Base = declarative_base()
engine = create_engine('sqlite:///' + os.path.join(BASEDIR, 'primus2azure.db'), echo=False)
Session = sessionmaker(bind=engine)

@contextmanager
def session_scope():
  session = Session()
  try:
    yield session
    session.commit()
  except:
    session.rollback()
    raise
  finally:
    session.close()

class User(Base):
  """
  Used mainly for keeping track of users which should be enabled/disabled.

  :immutable_id: Unique ID used in Azure
  :azure_user_id: Unique ID to access user information in Azure 
  :created: First time the user was created/added to Azure
  :synced: Last time the user was updated in Azure
  :is_active: If False user account must be set as disabled in Azure 
  """
  __tablename__ = 'users'
  immutable_id = Column(String(50), primary_key=True)
  azure_user_id = Column(String(50))
  created = Column(DateTime())
  synced = Column(DateTime())
  is_active = Column(Boolean())

Base.metadata.create_all(engine)
