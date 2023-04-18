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


    def open_labeled_logfile(self, logfile_name: str) -> TextIO:
        """
        opens the labeled log file placed inside the labeled_flows dir
        and stores the handle in self.open_handles
        creates the file if it isn't there
        @param logfile_name: conn.log, dns.log, arp.log etc
        """
        labeled_logfile_path = os.path.join(self.labels_dir, f'{logfile_name}.labeled')
        # create the file
        open(labeled_logfile_path, 'w').close()
        self.open_handles[logfile_name] = open(labeled_logfile_path, 'a')

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
                message = __database__.get_message(self.c1)
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True

                if utils.is_msg_intended_for(message, 'add_label'):


                    if file not in self.open_handles:
                        self.open_labeled_logfile(file)
                    labeled_log_file: TextIO = self.open_handles[file]

                    json.dump(flow, labeled_log_file)
                    labeled_log_file.write('\n')


            except KeyboardInterrupt:
                self.shutdown_gracefully()
                return True
            except Exception:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on the run() line {exception_line}', 0, 1)
                self.print(traceback.format_exc(), 0, 1)
                return True
