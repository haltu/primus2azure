import sys
from cx_Freeze import setup, Executable

import requests.certs
build_exe_options = {"include_files": [(requests.certs.where(), 'cacert.pem'), ('defaults.cfg', 'defaults.cfg'), ('example_config.cfg', 'primus2azure.cfg'), ('sample_input.csv', 'sample_input.csv')]}

setup(
  name="primus2azure",
  version="1.0",
  description="Primus to Azure sync",
  options={"build_exe": build_exe_options},
  executables=[Executable("app.py")]
)
