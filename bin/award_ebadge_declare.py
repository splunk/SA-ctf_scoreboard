# encode = utf-8

import os
import sys
import re

ta_name = 'SA-ctf_scoreboard'
ta_lib_name = 'sa_ctf_scoreboard'
pattern = re.compile(r"[\\/]etc[\\/]apps[\\/][^\\/]+[\\/]bin[\\/]?$")
new_paths = [path for path in sys.path if not pattern.search(path) or ta_name in path]
new_paths.insert(0, os.path.sep.join([os.path.dirname(__file__), ta_lib_name]))
sys.path = new_paths
