# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database.database import __database__
from slips_files.common.slips_utils import utils
from pathlib import Path
from typing import TextIO
import sys
import traceback
import json
import time
import os


class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'Labeler'
    description = 'Add labels to flows based on slips detections'
    authors = ['Alya Gomaa']

    def __init__(self, outputqueue, redis_port):
        time.sleep(5)
        multiprocessing.Process.__init__(self)
        self.outputqueue = outputqueue
        __database__.start(redis_port)
        self.c1 = __database__.subscribe('add_label')
        self.open_handles = {}

    def init_labels_dir(self):
        """ creates the labeled_flows dir if not there """
        self.labels_dir = os.path.join(__database__.get_output_dir(), 'labeled_flows/')
        p = Path(self.labels_dir)
        p.mkdir(parents=True, exist_ok=True)

    def shutdown_gracefully(self):
        for handle in self.open_handles.values():
            handle.close()
        # Confirm that the module is done processing
        __database__.publish('finished_modules', self.name)

    def run(self):
        # sleep 5s until all modules are started, the output dir is stored in the db
        # and then create the labeled dir inside of it
        time.sleep(5)
        self.init_labels_dir()

        #todo handle all input types, zeek suricata zeek tabs etc
        utils.drop_root_privs()
        while True:
            try:
              pass


            except KeyboardInterrupt:
                self.shutdown_gracefully()
                return True
            except Exception:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on the run() line {exception_line}', 0, 1)
                self.print(traceback.format_exc(), 0, 1)
                return True
