#!/usr/bin/env python3
# Stratosphere Linux IPS. A machine-learning Intrusion Detection System
# Copyright (C) 2021 Sebastian Garcia

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
# Contact: eldraco@gmail.com, sebastian.garcia@agents.fel.cvut.cz, stratosphere@aic.fel.cvut.cz

from slips_files.common.abstracts import Module
from slips_files.common.argparse import ArgumentParser
from slips_files.common.slips_utils import utils
from slips_files.core.database import __database__
import configparser
import signal
import sys
import redis
import os
import time
import shutil
from datetime import datetime
import socket
import warnings
import json
import pkgutil
import inspect
import modules
import importlib
import errno
import subprocess
import re
import random
from collections import OrderedDict
from distutils.dir_util import copy_tree
from daemon import Daemon
from multiprocessing import Queue

version = '0.9.3'

# Ignore warnings on CPU from tensorflow
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
# Ignore warnings in general
warnings.filterwarnings('ignore')
# ---------------------


class Main:
    def __init__(self, testing=False):
        self.name = 'Main'
        self.alerts_default_path = 'output/'
        self.mode = 'interactive'
        self.running_logfile = 'running_slips_info.txt'
        # slips picks a redis port from the following range
        self.start_port = 32768
        self.end_port = 32850
        # in testing mode we manually set the following params
        if not testing:
            self.pid = os.getpid()
            self.parse_arguments()
            # set self.config
            self.read_conf_file()
            self.check_given_flags()
            if not self.args.stopdaemon:
                # Check the type of input
                self.input_type, self.input_information, self.line_type = self.check_input_type()
                # If we need zeek (bro), test if we can run it.
                if self.check_zeek_or_bro():
                    self.prepare_zeek_scripts()
                self.prepare_output_dir()
                # this is the zeek dir slips will be using
                self.prepare_zeek_output_dir()

    def prepare_zeek_output_dir(self):
        from pathlib import Path
        without_ext = Path(self.input_information).stem
        self.zeek_folder = f'./zeek_files_{without_ext}/'


    def read_configuration(self, config, section, name):
        """Read the configuration file for what slips.py needs. Other processes also access the configuration"""
        try:
            return config.get(section, name)
        except (
            configparser.NoOptionError,
            configparser.NoSectionError,
            NameError,
        ):
            # There is a conf, but there is no option, or no section or no configuration file specified
            return False

    def get_host_ip(self):
        """
        Recognize the IP address of the machine
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('1.1.1.1', 80))
            ipaddr_check = s.getsockname()[0]
            s.close()
        except (socket.error):
            # not connected to the internet
            return None
        return ipaddr_check

    def store_host_ip(self):
        """
        Store the host IP address if input type is interface
        """
        if self.input_type != 'interface':
            return

        hostIP = self.get_host_ip()
        while True:
            try:
                __database__.set_host_ip(hostIP)
                break
            except redis.exceptions.DataError:
                self.print(
                    'Not Connected to the internet. Reconnecting in 10s.'
                )
                time.sleep(10)
                hostIP = self.get_host_ip()
        return hostIP

    def create_folder_for_logs(self):
        """
        Create a dir for logs if logs are enabled
        """
        logs_folder = utils.convert_format(datetime.now(), '%Y-%m-%d--%H-%M-%S')
        try:
            os.makedirs(logs_folder)
        except OSError as e:
            if e.errno != errno.EEXIST:
                # doesn't exist and can't create
                return False
        return logs_folder

    def check_redis_database(
        self, redis_host='localhost', redis_port=6379
    ) -> bool:
        """
        Check if we have redis-server running (this is the cache db it should always be running)
        """
        tries = 0
        while True:
            try:
                r = redis.StrictRedis(
                    host=redis_host,
                    port=redis_port,
                    db=1,
                    charset='utf-8',
                    decode_responses=True,
                )
                r.ping()
                return True
            except Exception as ex:
                # only try to open redi-server once.
                if tries == 2:
                    print('[Main] Problem starting redis cache database. Stopping')
                    self.terminate_slips()
                    return False

                print('[Main] Starting redis cache database..')
                os.system(
                    f'redis-server --daemonize yes  > /dev/null 2>&1'
                )
                # give the server time to start
                time.sleep(1)
                tries += 1


    def generate_random_redis_port(self):
        """
        Keeps trying to connect to random generated ports until we're connected.
        returns the used port
        """
        # generate a random unused port
        for port in range(self.start_port, self.end_port+1):
            # check if 1. we can connect
            # 2.server is not being used by another instance of slips
            # note: using r.keys() blocks the server
            try:
                connected = __database__.connect_to_redis_server(port)
                if connected:
                    server_used = len(list(__database__.r.keys())) < 2
                    if server_used:
                        # if the db managed to connect to this random port, then this is
                        # the port we'll be using
                        return port
            except redis.exceptions.ConnectionError:
                # Connection refused to this port
                continue
        else:
            # there's no usable port in this range
            print(f"All ports from {self.start_port} to {self.end_port} are used. "
                   "Unable to start slips.\n")
            return False


    def clear_redis_cache_database(
        self, redis_host='localhost', redis_port=6379
    ) -> bool:
        """
        Clear cache database
        """
        rcache = redis.StrictRedis(
            host=redis_host,
            port=redis_port,
            db=1,
            charset='utf-8',
            decode_responses=True,
        )
        rcache.flushdb()
        return True

    def check_zeek_or_bro(self):
        """
        Check if we have zeek or bro
        """
        self.zeek_bro = None
        if self.input_type not in ('pcap', 'interface'):
            return False

        if shutil.which('zeek'):
            self.zeek_bro = 'zeek'
        elif shutil.which('bro'):
            self.zeek_bro = 'bro'
        else:
            print('Error. No zeek or bro binary found.')
            self.terminate_slips()
            return False

        return self.zeek_bro

    def terminate_slips(self):
        """
        Do all necessary stuff to stop process any clear any files.
        """
        if self.mode == 'daemonized':
            self.daemon.stop()
        sys.exit(-1)

    def get_modules(self, to_ignore):
        """
        Get modules from the 'modules' folder.
        """
        # This plugins import will automatically load the modules and put them in
        # the __modules__ variable

        plugins = {}
        failed_to_load_modules = 0
        # Walk recursively through all modules and packages found on the . folder.
        # __path__ is the current path of this python program
        for loader, module_name, ispkg in pkgutil.walk_packages(
                modules.__path__, f'{modules.__name__}.'
        ):
            if any(module_name.__contains__(mod) for mod in to_ignore):
                continue
            # If current item is a package, skip.
            if ispkg:
                continue
            # to avoid loading everything in the dir,
            # only load modules that have the same name as the dir name
            dir_name = module_name.split('.')[1]
            file_name = module_name.split('.')[2]
            if dir_name != file_name:
                continue

            # Try to import the module, otherwise skip.
            try:
                # "level specifies whether to use absolute or relative imports. The default is -1 which
                # indicates both absolute and relative imports will be attempted. 0 means only perform
                # absolute imports. Positive values for level indicate the number of parent
                # directories to search relative to the directory of the module calling __import__()."
                module = importlib.import_module(module_name)
            except ImportError as e:
                print(
                    'Something wrong happened while importing the module {0}: {1}'.format(
                        module_name, e
                    )
                )
                failed_to_load_modules += 1
                continue

            # Walk through all members of currently imported modules.
            for member_name, member_object in inspect.getmembers(module):
                # Check if current member is a class.
                if inspect.isclass(member_object) and (issubclass(
                        member_object, Module
                ) and member_object is not Module):
                    plugins[member_object.name] = dict(
                        obj=member_object,
                        description=member_object.description,
                    )

        # Change the order of the blocking module(load it first)
        # so it can receive msgs sent from other modules
        if 'Blocking' in plugins:
            plugins = OrderedDict(plugins)
            # last=False to move to the beginning of the dict
            plugins.move_to_end('Blocking', last=False)

        return plugins, failed_to_load_modules

    def load_modules(self):
        to_ignore = self.get_disabled_modules()
        # Import all the modules
        modules_to_call = self.get_modules(to_ignore)[0]
        for module_name in modules_to_call:
            if module_name in to_ignore:
                continue

            module_class = modules_to_call[module_name]['obj']
            if 'p2ptrust' == module_name:
                ModuleProcess = module_class(
                    self.outputqueue,
                    self.config,
                    self.redis_port,
                    output_dir=self.args.output
                )
            else:
                ModuleProcess = module_class(
                    self.outputqueue,
                    self.config,
                    self.redis_port
                )
            ModuleProcess.start()
            __database__.store_process_PID(
                module_name, int(ModuleProcess.pid)
            )
            description = modules_to_call[module_name]['description']
            self.print(
                f'\t\tStarting the module {module_name} '
                f'({description}) '
                f'[PID {ModuleProcess.pid}]', 1, 0
                )
        # give outputprocess time to print all the started modules
        time.sleep(0.5)
        print('-' * 27)
        self.print(f"Disabled Modules: {to_ignore}", 1, 0)

    def setup_detailed_logs(self, LogsProcess):
        """
        Detailed logs are the ones created by logsProcess
        """
        do_logs = self.read_configuration(
            self.config, 'parameters', 'create_log_files'
        )
        # if -l is provided or create_log_files is yes then we will create log files
        if self.args.createlogfiles or do_logs == 'yes':
            # Create a folder for logs
            logs_dir = self.create_folder_for_logs()
            # Create the logsfile thread if by parameter we were told,
            # or if it is specified in the configuration
            self.logsProcessQueue = Queue()
            logs_process = LogsProcess(
                self.logsProcessQueue,
                self.outputqueue,
                self.args.verbose,
                self.args.debug,
                self.config,
                logs_dir,
                self.redis_port
            )
            logs_process.start()
            self.print(
                f'Started logsfiles thread '
                f'[PID {logs_process.pid}]', 1, 0
            )
            __database__.store_process_PID(
                'logsProcess', int(logs_process.pid)
            )
        else:
            # If self.args.nologfiles is False, then we don't want log files,
            # independently of what the conf says.
            logs_dir = False

    def prepare_zeek_scripts(self):
        """
        Adds local network to slips-conf.zeek
        """

        # get home network from slips.conf
        try:
            home_network = self.config.get('parameters', 'home_network')
        except (
            configparser.NoOptionError,
            configparser.NoSectionError,
            NameError,
        ):
            # There is a conf, but there is no option, or no section or no configuration file specified
            home_network = utils.home_network_ranges

        zeek_scripts_dir = f'{os.getcwd()}/zeek-scripts'
        # add local sites if not there
        is_local_nets_defined = False
        with open(f'{zeek_scripts_dir}/slips-conf.zeek', 'r') as slips_conf:
            if 'local_nets' in slips_conf.read():
                is_local_nets_defined = True

        if not is_local_nets_defined:
            with open(
                    f'{zeek_scripts_dir}/slips-conf.zeek', 'a'
            ) as slips_conf:
                # update home network
                slips_conf.write(
                    '\nredef Site::local_nets += { ' + home_network + ' };\n'
                )

        # # load all scripts in zeek-script dir
        # with open(zeek_scripts_dir + '/__load__.zeek','r') as f:
        #     loaded_scripts = f.read()
        # with open(zeek_scripts_dir + '/__load__.zeek','a') as f:
        #     for file_name in os.listdir(zeek_scripts_dir):
        #         # ignore the load file
        #         if file_name == '__load__.zeek':
        #             continue
        #         if file_name not in loaded_scripts:
        #             # found a file in the dir that isn't in __load__.zeek, add it
        #             f.write(f'\n@load ./{file_name}')

    def start_gui_process(self):
        # Get the type of output from the parameters
        # Several combinations of outputs should be able to be used
        if self.args.gui:
            # Create the curses thread
            guiProcessQueue = Queue()
            guiProcessThread = GuiProcess(
                guiProcessQueue, self.outputqueue, self.args.verbose,
                self.args.debug, self.config
            )
            guiProcessThread.start()
            self.print('quiet')


    def close_all_ports(self):
        """
        Closes all the redis ports
        """

        # close all ports in logfile
        failed_to_close = 0
        for pid in self.open_servers_PIDs:
            if self.flush_redis_server(pid=pid) and self.kill_redis_server(pid):
                port = self.open_servers_PIDs[pid]
                # self.remove_server_from_log(port)
            else:
                failed_to_close += 1
        killed_servers: int = len(self.open_servers_PIDs.keys()) - failed_to_close
        # print(f'Successfully closed {killed_servers} redis servers.')


        # closes all the ports in slips supported range of ports
        for port in range(self.start_port, self.end_port + 1):
            pid = self.get_pid_of_redis_server(port)
            if pid:
                self.flush_redis_server(pid=pid)
                self.kill_redis_server(pid)

        # print(f"Successfully closed all redis servers on ports {self.start_port} to {self.end_port}")
        print(f"Successfully closed all open redis servers")

        try:
            os.remove(self.running_logfile)
        except FileNotFoundError:
            pass
        self.terminate_slips()
        return

    def get_pid_of_redis_server(self, port: int) -> str:
        """
        Gets the pid of the redis server running on this port
        Returns str(port) or false if there's no redis-server running on this port
        """
        cmd = 'ps aux | grep redis-server'
        cmd_output = os.popen(cmd).read()
        for line in cmd_output.splitlines():
            if str(port) in line:
                pid = line.split()[1]
                return pid
        return False

    def update_local_TI_files(self):
        from modules.update_manager.update_file_manager import UpdateFileManager
        update_manager = UpdateFileManager(self.outputqueue, self.config, self.redis_port)
        update_manager.update_ports_info()
        update_manager.update_org_files()


    def add_metadata(self):
        """
        Create a metadata dir output/metadata/ that has a copy of slips.conf, whitelist.conf, current commit and date
        """
        metadata_dir = os.path.join(self.args.output, 'metadata')
        try:
            os.mkdir(metadata_dir)
        except FileExistsError:
            # if the file exists it will be overwritten
            pass

        # Add a copy of slips.conf
        config_file = self.args.config or 'slips.conf'
        shutil.copy(config_file, metadata_dir)
        # Add a copy of whitelist.conf
        whitelist = self.config.get('parameters', 'whitelist_path')
        shutil.copy(whitelist, metadata_dir)

        branch_info = utils.get_branch_info()
        commit, branch = None, None
        if branch_info != False:
            # it's false when we're in docker because there's no .git/ there
            commit, branch = branch_info[0], branch_info[1]
        now = datetime.now()

        self.info_path = os.path.join(metadata_dir, 'info.txt')
        with open(self.info_path, 'w') as f:
            f.write(f'Slips version: {version}\n'
                    f'File: {self.input_information}\n'
                    f'Branch: {branch}\n'
                    f'Commit: {commit}\n'
                    f'Slips start date: {now}\n'
                    )

        print(f'[Main] Metadata added to {metadata_dir}')
        return self.info_path

    def stop_core_processes(self):
        try:
            os.kill(int(self.PIDs['InputProcess']), signal.SIGKILL)
            self.PIDs.pop('InputProcess')
        except KeyError:
            pass

        if self.mode == 'daemonized':
            # when using -D,we kill the processes because
            # the queues are not there yet to send stop msgs
            for process in ('OutputProcess',
                            'ProfilerProcess',
                            'logsProcess'): #'EvidenceProcess',
                try:
                    os.kill(int(self.PIDs[process]), signal.SIGINT)
                except KeyError:
                    # logsprocess isn't started yet
                    pass
        else:
            # Send manual stops to the processes using queues
            stop_msg = 'stop_process'
            self.outputqueue.put(stop_msg)
            self.profilerProcessQueue.put(stop_msg)
            # self.evidenceProcessQueue.put(stop_msg)
            if hasattr(self, 'logsProcessQueue'):
                self.logsProcessQueue.put(stop_msg)



    def shutdown_gracefully(self):
        """
        Wait for all modules to confirm that they're done processing and then shutdown
        """

        try:
            if not self.args.stopdaemon:
                print('\n' + '-' * 27)
            print('Stopping Slips')

            # set analysis end date
            now = utils.convert_format(datetime.now(), utils.alerts_format)
            __database__.set_input_metadata({'analysis_end': now})
            # add slips end date in the metadata dir
            try:
                if 'yes' in self.enable_metadata.lower():
                    with open(self.info_path, 'a') as f:
                        f.write(f'Slips end date: {now}\n')
            except (NameError, AttributeError):
                # slips is shut down before enable_metadata is read from slips.conf
                pass

            # Stop the modules that are subscribed to channels
            __database__.publish_stop()
            finished_modules = []
            # get dict of PIDs spawned by slips
            self.PIDs = __database__.get_PIDs()

            # we don't want to kill this process
            try:
                self.PIDs.pop('slips.py')
                self.PIDs.pop('EvidenceProcess')
            except KeyError:
                pass
            slips_processes = len(list(self.PIDs.keys()))

            self.stop_core_processes()

            # only print that modules are still running once
            warning_printed = False

            # timeout variable so we don't loop forever
            # give slips enough time to close all modules - make sure all modules aren't considered 'busy' when slips stops
            max_loops = 430
            # loop until all loaded modules are finished
            if not self.args.stopdaemon:
                # in the case of -S, slips doesn't even start the modules,
                # so they don't publish in finished_modules. we don't need to wait for them we have to kill them
                try:
                    while (
                        len(finished_modules) < slips_processes and max_loops != 0
                    ):
                        # print(f"Modules not finished yet {set(loaded_modules) - set(finished_modules)}")
                        try:
                            message = self.c1.get_message(timeout=0.00000001)
                        except NameError:
                            # Sometimes the c1 variable does not exist yet. So just force the shutdown
                            message = {
                                'data': 'dummy_value_not_stopprocess',
                                'channel': 'finished_modules',
                            }

                        if message and message['data'] == 'stop_process':
                            continue
                        if utils.is_msg_intended_for(message, 'finished_modules'):
                            # all modules must reply with their names in this channel after
                            # receiving the stop_process msg
                            # to confirm that all processing is done and we can safely exit now
                            module_name = message['data']

                            if module_name not in finished_modules:
                                finished_modules.append(module_name)
                                try:
                                    os.kill(int(self.PIDs[module_name]), signal.SIGKILL)
                                except KeyError:
                                    pass

                                # remove module from the list of opened pids
                                self.PIDs.pop(module_name, None)


                                modules_left = len(list(self.PIDs.keys()))
                                # to vertically align them when printing
                                module_name = module_name + ' ' * (
                                    20 - len(module_name)
                                )
                                print(
                                    f'\t\033[1;32;40m{module_name}\033[00m \tStopped. \033[1;32;40m{modules_left}\033[00m left.'
                                )
                        max_loops -= 1
                        # after reaching the max_loops and before killing the modules that aren't finished,
                        # make sure we're not in the middle of processing
                        if len(self.PIDs) > 0 and max_loops < 2:
                            if not warning_printed:
                                # some modules publish in finished_modules channel before slips.py starts listening,
                                # but they finished gracefully.
                                # remove already stopped modules from PIDs dict
                                for module, pid in self.PIDs.items():
                                    try:
                                        # signal 0 is used to check if the pid exists
                                        os.kill(int(pid), 0)
                                    except ProcessLookupError:
                                        # pid doesn't exist because module already stopped
                                        finished_modules.append(module)

                                # exclude the module that are already stopped from the pending modules
                                pending_modules = [
                                    module
                                    for module in list(self.PIDs.keys())
                                    if module not in finished_modules
                                ]
                                if len(pending_modules) > 0:
                                    print(
                                        f'\n[Main] The following modules are busy working on your data.'
                                        f'\n\n{pending_modules}\n\n'
                                        'You can wait for them to finish, or you can press CTRL-C again to force-kill.\n'
                                    )
                                    warning_printed = True
                            # -P flag is only used in integration tests,
                            # so we don't care about the modules finishing their job when testing
                            # instead, kill them
                            if not self.args.port:
                                # delay killing unstopped modules
                                max_loops += 1
                                continue
                except KeyboardInterrupt:
                    # either the user wants to kill the remaining modules (pressed ctrl +c again)
                    # or slips was stuck looping for too long that the os sent an automatic sigint to kill slips
                    # pass to kill the remaining modules
                    pass

            # modules that aren't subscribed to any channel will always be killed and not stopped
            # comes here if the user pressed ctrl+c again
            for unstopped_proc, pid in self.PIDs.items():
                unstopped_proc = unstopped_proc + ' ' * (
                    20 - len(unstopped_proc)
                )
                try:
                    os.kill(int(pid), 9)
                    print(f'\t\033[1;32;40m{unstopped_proc}\033[00m \tKilled.')
                except ProcessLookupError:
                    print(
                        f'\t\033[1;32;40m{unstopped_proc}\033[00m \tAlready stopped.'
                    )
            # evidence process should be the last process to exit, so it can print detections of the
            # modules that are still processing
            try:
                os.kill(int(self.PIDs['EvidenceProcess']), signal.SIGINT)
            except KeyError:
                pass

            # save redis database if '-s' is specified
            if self.args.save:
                # Create a new dir to store backups
                backups_dir = os.path.join(os.getcwd(), 'redis_backups/')
                try:
                    os.mkdir(backups_dir)
                except FileExistsError:
                    pass
                # The name of the interface/pcap/nfdump/binetflow used is in self.input_information
                # if the input is a zeek dir, remove the / at the end
                if self.input_information.endswith('/'):
                    self.input_information = self.input_information[:-1]
                # We need to separate it from the path
                self.input_information = os.path.basename(self.input_information)
                # Remove the extension from the filename
                try:
                    self.input_information = self.input_information[
                        : self.input_information.index('.')
                    ]
                except ValueError:
                    # it's a zeek dir
                    pass
                # Give the exact path to save(), this is where our saved .rdb backup will be
                rdb_filepath = os.path.join(backups_dir, self.input_information)
                __database__.save(rdb_filepath)
                # info will be lost only if you're out of space and redis can't write to dump.rdb, otherwise you're fine
                print(
                    '[Main] [Warning] stop-writes-on-bgsave-error is set to no, information may be lost in the redis backup file.'
                )

            # make sure that redis isn't saving snapshots whether -s is given or not
            __database__.disable_redis_snapshots()

            # if store_a_copy_of_zeek_files is set to yes in slips.conf, copy the whole zeek_files dir to the output dir
            try:
                store_a_copy_of_zeek_files = self.config.get(
                    'parameters', 'store_a_copy_of_zeek_files'
                )
                store_a_copy_of_zeek_files = (
                    False
                    if 'no' in store_a_copy_of_zeek_files.lower()
                    else True
                )
            except (
                configparser.NoOptionError,
                configparser.NoSectionError,
                NameError,
            ):
                # There is a conf, but there is no option, or no section or no configuration file specified
                store_a_copy_of_zeek_files = False
            if store_a_copy_of_zeek_files and self.input_type in ('pcap', 'interface'):
                # this is where the copy will be stored
                dest_zeek_dir = os.path.join(self.args.output, 'zeek_files')
                copy_tree(self.zeek_folder, dest_zeek_dir)
                print(
                    f'[Main] Stored a copy of zeek files to {dest_zeek_dir}'
                )

            # if delete_zeek_files is set to yes in slips.conf,
            # delete the whole zeek_files
            try:
                delete_zeek_files = self.config.get(
                    'parameters', 'delete_zeek_files'
                )
                delete_zeek_files = (
                    False if 'no' in delete_zeek_files.lower() else True
                )
            except (
                configparser.NoOptionError,
                configparser.NoSectionError,
                NameError,
            ):
                # There is a conf, but there is no option, or no section or no configuration file specified
                delete_zeek_files = True

            if delete_zeek_files:
                shutil.rmtree('zeek_files')

            if self.mode == 'daemonized':
                profilesLen = str(__database__.getProfilesLen())
                print(f'Total Number of Profiles in DB: {profilesLen}.')
                self.daemon.stop()
            os._exit(-1)
            return True
        except KeyboardInterrupt:
            return False

    def get_open_redis_servers(self) -> dict:
        """
        Returns the dict of PIDs and ports of the redis servers started by slips
        """
        self.open_servers_PIDs = {}
        try:
            with open(self.running_logfile, 'r') as f:
                for line in f.read().splitlines():
                    # skip comments
                    if (
                        line.startswith('#')
                        or line.startswith('Date')
                        or len(line) < 3
                    ):
                        continue
                    line = line.split(',')
                    pid, port = line[3], line[2]
                    self.open_servers_PIDs[pid] = port
            return self.open_servers_PIDs
        except FileNotFoundError:
            # print(f"Error: {self.running_logfile} is not found. Can't kill open servers. Stopping.")
            return {}

    def print_open_redis_servers(self):
        """
        Returns a dict {counter: (used_port,pid) }
        """
        open_servers = {}
        print(f"[0] Close all servers")
        try:
            with open(self.running_logfile, 'r') as f:
                line_number = 0
                for line in f.read().splitlines():
                    # skip comments
                    if (
                        line.startswith('#')
                        or line.startswith('Date')
                        or len(line) < 3
                    ):
                        continue
                    line_number += 1
                    line = line.split(',')
                    file, port, pid = line[1], line[2], line[3]
                    print(f"[{line_number}] {file} - port {port}")
                    open_servers[line_number] = (port, pid)
                return open_servers
        except FileNotFoundError:
            print(f"{self.running_logfile} is not found. Can't get open redis servers. Stopping.")
            return False


    def get_port_of_redis_server(self, pid: str):
        """
        returns the port of the redis running on this pid
        """
        cmd = 'ps aux | grep redis-server'
        cmd_output = os.popen(cmd).read()
        for line in cmd_output.splitlines():
            if str(pid) in line:
                port = line.split(':')[-1]
                return port
        return False


    def flush_redis_server(self, pid: str='', port: str=''):
        """
        Flush the redis server on this pid, only 1 param should be given, pid or port
        :param pid: can be False if port is given
        Gets the pid of the port is not given
        """
        if not port and not pid:
            return False

        # sometimes the redis port is given, no need to get it manually
        if not port and pid:
            if not hasattr(self, 'open_servers_PIDs'):
                self.get_open_redis_servers()
            port = self.open_servers_PIDs.get(str(pid), False)
            if not port:
                # try to get the port using a cmd
                port = self.get_port_of_redis_server(pid)
        port = str(port)

        # clear the server opened on this port
        try:
            # if connected := __database__.connect_to_redis_server(port):
            # noinspection PyTypeChecker
            #todo move this to the db
            r = redis.StrictRedis(
                    host='localhost',
                    port=port,
                    db=0,
                    charset='utf-8',
                    socket_keepalive=True,
                    decode_responses=True,
                    retry_on_timeout=True,
                    health_check_interval=20,
                    )
            r.flushall()
            r.flushdb()
            r.script_flush()
            return True
        except redis.exceptions.ConnectionError:
            # server already killed!
            return False


    def kill_redis_server(self, pid):
        """
        Kill the redis server on this pid
        """
        try:
            pid = int(pid)
        except ValueError:
            # The server was killed before logging its PID
            # the pid of it is 'not found'
            return False

        # signal 0 is to check if the process is still running or not
        # it returns 1 if the process used_redis_servers.txt exited
        try:
            # check if the process is still running
            while os.kill(pid, 0) != 1:
                # sigterm is 9
                os.kill(pid, 9)
        except ProcessLookupError:
            # ProcessLookupError: process already exited, sometimes this exception is raised
            # but the process is still running, keep trying to kill it
            return True
        except PermissionError:
            # PermissionError happens when the user tries to close redis-servers
            # opened by root while he's not root,
            # or when he tries to close redis-servers
            # opened without root while he's root
            return False
        return True

    def remove_old_logline(self):
        """
        The only line with 6379 should be the last line, remove all the ones above
        """
        redis_port = str(6379)
        tmpfile = 'tmp_running_slips_log.txt'
        with open(self.running_logfile, 'r') as logfile:
            with open(tmpfile, 'w') as tmp:
                all_lines = logfile.read().splitlines()
                # the only one that should have 6379
                last_line = all_lines[-1]
                # we want to delete the old log line containing this port
                # but leave the new one (the last one)

                for line in all_lines[:-1]:
                    if redis_port not in line:
                        tmp.write(f'{line}\n')

                # write the last line
                tmp.write(all_lines[-1]+'\n')
        # replace file with original name
        os.replace(tmpfile, self.running_logfile)


    def remove_server_from_log(self, redis_port):
        """ deletes the server running on the given pid from running_slips_logs """
        redis_port = str(redis_port)
        tmpfile = 'tmp_running_slips_log.txt'
        with open(self.running_logfile, 'r') as logfile:
            with open(tmpfile, 'w') as tmp:
                all_lines = logfile.read().splitlines()
                # delete the line using that port
                for line in all_lines:
                    if redis_port not in line:
                        tmp.write(f'{line}\n')

        # replace file with original name
        os.replace(tmpfile, self.running_logfile)


    def close_open_redis_servers(self):
        """
        Function to close unused open redis-servers based on what the user chooses
        """
        if not hasattr(self, 'open_servers_PIDs'):
            # fill the dict
            self.get_open_redis_servers()

        # if len(self.open_servers_PIDs) == 0:
        #     print('No unused open servers to kill.')
        #     sys.exit(-1)
        #     return
        try:
            print(f"Choose which one to kill [0,1,2 etc..]\n")
            # open_servers {1: (port,pid),...}}
            open_servers:dict = self.print_open_redis_servers()
            if not open_servers:
                self.terminate_slips()

            server_to_close = input()
            # close all ports in running_slips_logs.txt and in our supported range
            if server_to_close == '0':
                self.close_all_ports()

            if len(open_servers) > 0:
                try:
                    pid = open_servers[int(server_to_close)][1]
                    port = open_servers[int(server_to_close)][0]
                    if self.flush_redis_server(pid=pid) and self.kill_redis_server(pid):
                        print(f"Killed redis server on port {port}.")
                    else:
                        print(f"Redis server running on port {port} "
                              f"is either already killed or you don't have "
                              f"enough permission to kill it.")
                    self.remove_server_from_log(port)
                except (KeyError, ValueError):
                    print(f"Invalid input {server_to_close}")
        except KeyboardInterrupt:
            pass
        self.terminate_slips()


    def is_debugger_active(self) -> bool:
        """Return if the debugger is currently active"""
        gettrace = getattr(sys, 'gettrace', lambda: None)
        return gettrace() is not None

    def prepare_output_dir(self):
        """
        :param self.input_information: either an interface or a filename (wlp3s0, sample.pcap, zeek_dir/ etc.)
        """
        # default output/
        if '-o' in sys.argv:
            # -o is given
            # Create output folder for alerts.log and
            # alerts.json if it doesn't  exist
            files_to_clear = ('alerts.json', 'alerts.log', 'errors.log', 'slips.log')
            for file in files_to_clear:
                try:
                    file = os.path.join(self.args.output, file)
                    os.remove(file)
                except OSError:
                    # they weren't created in the first place
                    pass
            return

        # self.args.output is the same as self.alerts_default_path
        self.input_information = os.path.normpath(self.input_information)
        # now that slips can run several instances,
        # each created dir will be named after the instance
        # that created it
        # it should be output/wlp3s0
        self.args.output = os.path.join(
            self.alerts_default_path,
            os.path.basename(self.input_information)  # get pcap name from path
        )
        # add timestamp to avoid conflicts wlp3s0_2022-03-1_03:55
        ts = utils.convert_format(datetime.now(), '%Y-%m-%d_%H:%M:%S')
        self.args.output += f'_{ts}/'

        if not os.path.exists(self.args.output):
            os.makedirs(self.args.output)

        # print(f'[Main] Storing Slips logs in {self.args.output}')

    def parse_arguments(self):
        # Parse the parameters
        slips_conf_path = os.path.join(os.getcwd() ,'slips.conf')
        parser = ArgumentParser(
            usage='./slips.py -c <configfile> [options] [file]', add_help=False
        )
        parser.add_argument(
            '-c',
            '--config',
            metavar='<configfile>',
            action='store',
            required=False,
            default=slips_conf_path,
            help='Path to the Slips config file.',
        )
        parser.add_argument(
            '-v',
            '--verbose',
            metavar='<verbositylevel>',
            action='store',
            required=False,
            type=int,
            help='Verbosity level. This logs more info about slips.',
        )
        parser.add_argument(
            '-e',
            '--debug',
            metavar='<debuglevel>',
            action='store',
            required=False,
            type=int,
            help='Debugging level. This shows more detailed errors.',
        )
        parser.add_argument(
            '-f',
            '--filepath',
            metavar='<file>',
            action='store',
            required=False,
            help='read a Zeek folder, Argus binetflow, pcapfile or nfdump.',
        )
        parser.add_argument(
            '-i',
            '--interface',
            metavar='<interface>',
            action='store',
            required=False,
            help='Read packets from an interface.',
        )
        parser.add_argument(
            '-l',
            '--createlogfiles',
            action='store_true',
            required=False,
            help='Create log files with all the traffic info and detections.',
        )
        parser.add_argument(
            '-F',
            '--pcapfilter',
            action='store',
            required=False,
            type=str,
            help='packet filter for Zeek. BPF style.',
        )
        parser.add_argument(
            '-G',
            '--gui',
            help='Use the GUI interface.',
            required=False,
            default=False,
            action='store_true',
        )
        parser.add_argument(
            '-cc',
            '--clearcache',
            action='store_true',
            required=False,
            help='Clear the cache database.',
        )
        parser.add_argument(
            '-p',
            '--blocking',
            help='Allow Slips to block malicious IPs. Requires root access. Supported only on Linux.',
            required=False,
            default=False,
            action='store_true',
        )
        parser.add_argument(
            '-cb',
            '--clearblocking',
            help='Flush and delete slipsBlocking iptables chain',
            required=False,
            default=False,
            action='store_true',
        )
        parser.add_argument(
            '-o',
            '--output',
            action='store',
            required=False,
            default=self.alerts_default_path,
            help='Store alerts.json and alerts.txt in the provided folder.',
        )
        parser.add_argument(
            '-s',
            '--save',
            action='store_true',
            required=False,
            help='To Save redis db to disk. Requires root access.',
        )
        parser.add_argument(
            '-d',
            '--db',
            action='store',
            required=False,
            help='To read a redis (rdb) saved file. Requires root access.',
        )
        parser.add_argument(
            '-D',
            '--daemon',
            required=False,
            default=False,
            action='store_true',
            help='run slips in daemon mode, not interactive',
        )
        parser.add_argument(
            '-S',
            '--stopdaemon',
            required=False,
            default=False,
            action='store_true',
            help='Stop slips daemon',
        )
        parser.add_argument(
            '-k',
            '--killall',
            action='store_true',
            required=False,
            help='Kill all unused redis servers',
        )
        parser.add_argument(
            '-m',
            '--multiinstance',
            action='store_true',
            required=False,
            help='Run multiple instances of slips, don\'t overwrite the old one',
        )
        parser.add_argument(
            '-P',
            '--port',
            action='store',
            required=False,
            help='The redis-server port to use',
        )
        parser.add_argument(
            '-V',
            '--version',
            action='store_true',
            required=False,
            help='Print Slips Version',
        )
        parser.add_argument(
            '-h', '--help', action='help', help='command line help'
        )
        self.args = parser.parse_args()

    def read_conf_file(self):
        # don't use '%' for interpolation.
        self.config = configparser.ConfigParser(interpolation=None)
        try:
            with open(self.args.config) as source:
                self.config.read_file(source)
        except (IOError, TypeError):
            pass

        return self.config

    def log_redis_server_PID(self, redis_port, redis_pid):
        now = utils.convert_format(datetime.now(), utils.alerts_format)

        # used in case we need to remove the line using 6379 from running logfile
        with open(self.running_logfile, 'a') as f:
            # add the header lines if the file is newly created
            if f.tell() == 0:
                f.write(
                    '# This file contains a list of used redis ports.\n'
                    '# Once a server is killed, it will be removed from this file.\n'
                    'Date, File or interface, Used port, Server PID,'
                    ' Output Zeek Dir, Logs Dir, Is Daemon, Save the DB\n'
                )

            f.write(
                f'{now},{self.input_information},{redis_port},'
                f'{redis_pid},{self.zeek_folder},{self.args.output},'
                f'{bool(self.args.daemon)},{self.args.save}\n'
            )

        if redis_port == 6379:
            # remove the old logline using this port
            self.remove_old_logline()

    def set_mode(self, mode, daemon=''):
        """
        Slips has 2 modes, daemonized and interactive, this function
        sets up the mode so that slips knows in which mode it's operating
        :param mode: daemonized of interavtive
        :param daemon: Daemon() instance
        """
        self.mode = mode
        self.daemon = daemon

    def log(self, txt):
        """
        Is used instead of print for daemon debugging
        """
        with open(self.daemon.stdout, 'a') as f:
            f.write(f'{txt}\n')

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the processes into account
        :param verbose:
            0 - don't print
            1 - basic operation/proof of work
            2 - log I/O operations and filenames
            3 - log database/profile/timewindow changes
        :param debug:
            0 - don't print
            1 - print exceptions
            2 - unsupported and unhandled types (cases that may cause errors)
            3 - red warnings that needs examination - developer warnings
        :param text: text to print. Can include format like f'Test {here}'
        """

        levels = f'{verbose}{debug}'
        self.outputqueue.put(f'{levels}|{self.name}|{text}')

    def get_disabled_modules(self) -> list:
        to_ignore = self.read_configuration(
            self.config, 'modules', 'disable'
        )
        use_p2p = self.read_configuration(
            self.config, 'P2P', 'use_p2p'
        )

        if not to_ignore:
            return []
        # Convert string to list
        to_ignore = (
            to_ignore.replace('[', '')
                .replace(']', '')
                .replace(' ', '')
                .split(',')
        )
        # Ignore exporting alerts module if export_to is empty
        export_to = (
            self.config.get('ExportingAlerts', 'export_to')
                .rstrip('][')
                .replace(' ', '')
                .lower()
        )
        if (
                'stix' not in export_to
                and 'slack' not in export_to
                and 'json' not in export_to
        ):
            to_ignore.append('exporting_alerts')
        if (
                not use_p2p
                or use_p2p == 'no'
                or not self.args.interface
        ):
            to_ignore.append('p2ptrust')

        # ignore CESNET sharing module if send and receive are are disabled in slips.conf
        send_to_warden = self.config.get(
            'CESNET', 'send_alerts'
        ).lower()
        receive_from_warden = self.config.get(
            'CESNET', 'receive_alerts'
        ).lower()
        if 'no' in send_to_warden and 'no' in receive_from_warden:
            to_ignore.append('CESNET')
        # don't run blocking module unless specified
        if (
                not self.args.clearblocking
                and not self.args.blocking
                or (self.args.blocking and not self.args.interface)
        ):  # ignore module if not using interface
            to_ignore.append('blocking')

        # leak detector only works on pcap files
        if self.input_type != 'pcap':
            to_ignore.append('leak_detector')

        return to_ignore

    def handle_flows_from_stdin(self, input_information):
        """
        Make sure the stdin line type is valid (argus, suricata, or zeek)
        """
        if input_information.lower() not in (
                'argus',
                'suricata',
                'zeek',
        ):
            print(
                f'[Main] Invalid file path {input_information}. Stopping.'
            )
            sys.exit(-1)
            return False

        if self.mode == 'daemonized':
            print(
                "Can't read input from stdin in daemonized mode. "
                "Stopping"
            )
            sys.exit(-1)
            return False
        line_type = input_information
        input_type = 'stdin'
        return input_type, line_type.lower()

    def load_db(self):
        self.input_type = 'database'
        # self.input_information = 'database'
        from slips_files.core.database import __database__
        __database__.start(self.config, 6379)
        if not __database__.load(self.args.db):
            print(f'Error loading the database {self.args.db}')
        else:
            redis_port = 6379
            self.input_information = self.args.db
            __database__.connect_to_redis_server(redis_port)
            __database__.enable_redis_snapshots()
            #todo see why the dumps.rdb isn't loaded in 6379
            redis_pid = __database__.get_redis_server_PID(self.mode, redis_port)
            self.log_redis_server_PID(redis_port, redis_pid)

            print(
                f'{self.args.db} loaded successfully. Run ./kalipso.sh and choose port 6379'
            )
            __database__.disable_redis_snapshots()

        self.terminate_slips()

    def get_input_file_type(self, input_information):
        """
        input_information: given file
        returns binetflow, pcap, nfdump, zeek_folder, suricata, etc.
        """
        # default value
        input_type = 'file'
        # Get the type of file
        cmd_result = subprocess.run(
            ['file', input_information], stdout=subprocess.PIPE
        )
        # Get command output
        cmd_result = cmd_result.stdout.decode('utf-8')

        if 'pcap' in cmd_result:
            input_type = 'pcap'
        elif 'dBase' in cmd_result:
            input_type = 'nfdump'
            if shutil.which('nfdump') is None:
                # If we do not have nfdump, terminate Slips.
                print(
                    'nfdump is not installed. terminating slips.'
                )
                self.terminate_slips()
        elif 'CSV' in cmd_result:
            input_type = 'binetflow'
        elif 'directory' in cmd_result:
            input_type = 'zeek_folder'
        else:
            # is it a zeek log file or suricata, binetflow tabs, or binetflow comma separated file?
            # use first line to determine
            with open(input_information, 'r') as f:
                while True:
                    # get the first line that isn't a comment
                    first_line = f.readline().replace('\n', '')
                    if not first_line.startswith('#'):
                        break
            if 'flow_id' in first_line:
                input_type = 'suricata'
            else:
                # this is a text file, it can be binetflow or zeek_log_file
                try:
                    # is it a json log file
                    json.loads(first_line)
                    input_type = 'zeek_log_file'
                except json.decoder.JSONDecodeError:
                    # this is a tab separated file
                    # is it zeek log file or binetflow file?
                    tabs_found = re.search(
                        '\s{1,}-\s{1,}', first_line
                    )
                    if (
                            '->' in first_line
                            or 'StartTime' in first_line
                    ):
                        # tab separated files are usually binetflow tab files
                        input_type = 'binetflow-tabs'
                    elif tabs_found:
                        input_type = 'zeek_log_file'

        return input_type

    def check_input_type(self) -> tuple:
        """
        returns line_type, input_type, input_information
        supported input types are:
            interface, argus, suricata, zeek, nfdump, db
        supported self.input_information:
            given filepath, interface or type of line given in stdin
        """
        # only defined in stdin lines
        line_type = False
        # -I
        if self.args.interface:
            input_information = self.args.interface
            input_type = 'interface'
            # return input_type, self.input_information
            return input_type, input_information, line_type

        if self.args.db:
            self.load_db()
            return

        if not self.args.filepath:
            print('[Main] You need to define an input source.')
            sys.exit(-1)
        # -f file/stdin-type
        input_information = self.args.filepath
        if os.path.exists(input_information):
            input_type = self.get_input_file_type(input_information)
        else:
            input_type, line_type = self.handle_flows_from_stdin(
                input_information
            )

        return input_type, input_information, line_type

    def check_given_flags(self):
        """
        check the flags that don't reuiqre starting slips
        for ex: clear db, clear blocking, killling all servers, stopping the daemon, etc.
        """
        if (self.args.verbose and int(self.args.verbose) > 3) or (
            self.args.debug and int(self.args.debug) > 3
        ):
            print('Debug and verbose values range from 0 to 3.')
            self.terminate_slips()

        # Check if redis server running
        if self.check_redis_database() is False:
            print('Redis database is not running. Stopping Slips')
            self.terminate_slips()

        # Clear cache if the parameter was included
        if self.args.clearcache:
            print('Deleting Cache DB in Redis.')
            self.clear_redis_cache_database()
            self.terminate_slips()

        # kill all open unused redis servers if the parameter was included
        if self.args.killall:
            self.close_open_redis_servers()
            self.terminate_slips()

        if self.args.version:
            self.print_version()
            self.terminate_slips()

        if self.args.clearblocking:
            if os.geteuid() != 0:
                print(
                    'Slips needs to be run as root to clear the slipsBlocking chain. Stopping.'
                )
                self.terminate_slips()
            else:
                # start only the blocking module process and the db
                from slips_files.core.database import __database__
                from multiprocessing import Queue
                from modules.blocking.blocking import Module

                blocking = Module(Queue(), self.config)
                blocking.start()
                blocking.delete_slipsBlocking_chain()
                # Tell the blocking module to clear the slips chain
                self.shutdown_gracefully()

        # Check if user want to save and load a db at the same time
        if self.args.save:
            # make sure slips is running as root
            if os.geteuid() != 0:
                print(
                    'Slips needs to be run as root to save the database. Stopping.'
                )
                self.terminate_slips()
            if self.args.db:
                print("Can't use -s and -b together")
                self.terminate_slips()

    def set_input_metadata(self):
        """
        save info about name, size, analysis start date in the db
        """
        now = utils.convert_format(datetime.now(), utils.alerts_format)
        info = {
            'slips_version': version,
            'name': self.input_information,
            'analysis_start': now,

        }

        size_in_mb = '-'
        if self.args.filepath not in (False, None) and os.path.exists(self.args.filepath):
            size = os.stat(self.args.filepath).st_size
            size_in_mb = float(size) / (1024 * 1024)
            size_in_mb = format(float(size_in_mb), '.2f')

        info.update({
            'size_in_MB': size_in_mb,
        })
        # analysis end date will be set in shutdowngracefully
        # file(pcap,netflow, etc.) start date will be set in
        __database__.set_input_metadata(info)

    def check_blocking_permissions(self):
        """
        Check if the user blocks on interface, does not make sense to block on files
        """

        if (
            self.args.interface
            and self.args.blocking
            and os.geteuid() != 0
        ):
            # If the user wants to blocks,we need permission to modify iptables
            print(
                '[Main] Run Slips with sudo to enable the blocking module.'
            )
            self.shutdown_gracefully()

    def setup_print_levels(self):
        """
        setup debug and verose levels
        """
        # Any verbosity passed as parameter overrides the configuration. Only check its value
        if self.args.verbose == None:
            # Read the verbosity from the config
            try:
                self.args.verbose = int(
                    self.config.get('parameters', 'verbose')
                )
            except (
                configparser.NoOptionError,
                configparser.NoSectionError,
                NameError,
                ValueError,
            ):
                # There is a conf, but there is no option, or no section or no configuration file specified
                # By default, 1
                self.args.verbose = 1

        # Limit any verbosity to > 0
        if self.args.verbose < 1:
            self.args.verbose = 1

        # Any debuggsity passed as parameter overrides the configuration. Only check its value
        if self.args.debug == None:
            # Read the debug from the config
            try:
                self.args.debug = int(
                    self.config.get('parameters', 'debug')
                )
            except (
                configparser.NoOptionError,
                configparser.NoSectionError,
                NameError,
                ValueError,
            ):
                # There is a conf, but there is no option, or no section or no configuration file specified
                # By default, 0
                self.args.debug = 0

        # Limit any debuggisity to > 0
        if self.args.debug < 0:
            self.args.debug = 0


    def check_output_redirection(self) -> tuple:
        """
        Determine where slips will place stdout, stderr and logfile based on slips mode
        """
        # lsof will provide a list of all open fds belonging to slips
        command = f'lsof -p {self.pid}'
        result = subprocess.run(command.split(), capture_output=True)
        # Get command output
        output = result.stdout.decode('utf-8')
        # if stdout is being redirected we'll find '1w' in one of the lines
        # 1 means stdout, w means write mode
        # by default, stdout is not redirected
        current_stdout = ''
        for line in output.splitlines():
            if '1w' in line:
                # stdout is redirected, get the file
                current_stdout = line.split(' ')[-1]
                break

        if self.mode == 'daemonized':
            stderr = self.daemon.stderr
            slips_logfile = self.daemon.stdout
        else:
            stderr = os.path.join(self.args.output, 'errors.log')
            slips_logfile = os.path.join(self.args.output, 'slips.log')
        return (current_stdout, stderr, slips_logfile)

    def print_version(self):
        slips_version = f'Slips. Version {version}'
        branch_info = utils.get_branch_info()
        if branch_info != False:
            # it's false when we're in docker because there's no .git/ there
            commit = branch_info[0]
            slips_version += f' ({commit[:8]})'
        print(slips_version)

    def start(self):
        """Main Slips Function"""
        try:

            self.print_version()

            print('https://stratosphereips.org')
            print('-' * 27)

            self.check_blocking_permissions()
            """
            Import modules here because if user wants to run "./slips.py --help" it should never throw error. 
            """
            from multiprocessing import Queue
            from slips_files.core.inputProcess import InputProcess
            from slips_files.core.outputProcess import OutputProcess
            from slips_files.core.profilerProcess import ProfilerProcess
            from slips_files.core.guiProcess import GuiProcess
            from slips_files.core.logsProcess import LogsProcess
            from slips_files.core.evidenceProcess import EvidenceProcess

            self.setup_print_levels()
            ##########################
            # Creation of the threads
            ##########################
            from slips_files.core.database import __database__

            # get the port that is going to be used for this instance of slips
            if self.args.port:
                self.redis_port = int(self.args.port)
            elif self.args.multiinstance:
                self.redis_port = self.generate_random_redis_port()
                if not self.redis_port:
                    # all ports are unavailable
                    inp = input("Press Enter to close all ports.\n")
                    if inp == '':
                        self.close_all_ports()
                    self.terminate_slips()
            else:
                self.redis_port = 6379


            # Output thread. outputprocess should be created first because it handles
            # the output of the rest of the threads.
            self.outputqueue = Queue()

            # if stdout is redirected to a file,
            # tell outputProcess.py to redirect it's output as well
            current_stdout, stderr, slips_logfile = self.check_output_redirection()
            output_process = OutputProcess(
                self.outputqueue,
                self.args.verbose,
                self.args.debug,
                self.config,
                self.redis_port,
                stdout=current_stdout,
                stderr=stderr,
                slips_logfile=slips_logfile,
            )
            # this process starts the db
            output_process.start()

            __database__.set_slips_mode(self.mode)
            self.set_input_metadata()
            if self.args.save:
                __database__.enable_redis_snapshots()
            else:
                __database__.disable_redis_snapshots()

            if self.mode == 'daemonized':
                std_files = {
                    'stderr': self.daemon.stderr,
                    'stdout': self.daemon.stdout,
                    'stdin': self.daemon.stdin,
                    'pidfile': self.daemon.pidfile,
                    'logsfile': self.daemon.logsfile
                }
            else:
                std_files = {
                    'stderr': stderr,
                    'stdout': slips_logfile,
                }

            __database__.store_std_file(**std_files)

            # log the PID of the started redis-server
            redis_pid = __database__.get_redis_server_PID(self.mode, self.redis_port)
            self.log_redis_server_PID(self.redis_port, redis_pid)
            __database__.store_process_PID('OutputProcess', int(output_process.pid))

            self.print(f'Using redis server on port: {self.redis_port}', 1, 0)
            self.print(f'Started main program [PID {self.pid}]', 1, 0)
            self.print(f'Started output thread [PID {output_process.pid}]', 1, 0)
            self.print('Starting modules', 0, 1)


            # if slips is given a .rdb file, don't load the modules as we don't need them
            if not self.args.db:
                # update local files before starting modules
                self.update_local_TI_files()
                self.load_modules()


            # self.start_gui_process()


            # call shutdown_gracefully on sigterm
            def sig_handler(sig, frame):
                self.shutdown_gracefully()
            # The signals SIGKILL and SIGSTOP cannot be caught, blocked, or ignored.
            signal.signal(signal.SIGTERM, sig_handler)


            logs_dir = self.setup_detailed_logs(LogsProcess)


            self.evidenceProcessQueue = Queue()
            evidence_process = EvidenceProcess(
                self.evidenceProcessQueue,
                self.outputqueue,
                self.config,
                self.args.output,
                logs_dir,
                self.redis_port,
            )
            evidence_process.start()
            self.print(
                f'Started Evidence Process '
                f'[PID {evidence_process.pid}]', 1, 0
            )
            __database__.store_process_PID(
                'EvidenceProcess',
                int(evidence_process.pid)
            )
            __database__.store_process_PID(
                'slips.py',
                int(self.pid)
            )

            self.profilerProcessQueue = Queue()
            profiler_process = ProfilerProcess(
                self.profilerProcessQueue,
                self.outputqueue,
                self.args.verbose,
                self.args.debug,
                self.config,
                self.redis_port,
            )
            profiler_process.start()
            self.print(
                f'Started Profiler Process '
                f'[PID {profiler_process.pid}]', 1, 0
            )
            __database__.store_process_PID(
                'ProfilerProcess',
                int(profiler_process.pid)
            )

            self.c1 = __database__.subscribe('finished_modules')

            # Input process
            # Create the input process and start it
            inputProcess = InputProcess(
                self.outputqueue,
                self.profilerProcessQueue,
                self.input_type,
                self.input_information,
                self.config,
                self.args.pcapfilter,
                self.zeek_bro,
                self.zeek_folder,
                self.line_type,
                self.redis_port,
            )
            inputProcess.start()
            self.print(
                f'Started input thread '
                f'[PID {inputProcess.pid}]', 1, 0
            )
            __database__.store_process_PID(
                'InputProcess',
                int(inputProcess.pid)
            )
            self.zeek_folder = inputProcess.zeek_folder
            # warn about unused open redis servers
            open_servers = len(self.get_open_redis_servers())
            if open_servers > 1:
                self.print(
                    f'Warning: You have {open_servers} '
                    f'redis servers running. '
                    f'Run Slips with --killall to stop them.'
                )

            self.enable_metadata = self.read_configuration(
                                                self.config,
                                                'parameters',
                                                'metadata_dir'
                                                )

            if 'yes' in self.enable_metadata.lower():
                self.info_path = self.add_metadata()

            hostIP = self.store_host_ip()

            # Check every 5 secs if we should stop slips or not
            sleep_time = 5
            # In each interval we check if there has been any modifications to
            # the database by any module.
            # If not, wait this amount of intervals and then stop slips.
            # We choose 6 to wait 30 seconds.
            max_intervals_to_wait = 4
            intervals_to_wait = max_intervals_to_wait
            slips_internal_time = 0
            while True:
                message = self.c1.get_message(timeout=0.01)
                if (
                    message
                    and utils.is_msg_intended_for(message, 'finished_modules')
                    and message['data'] == 'stop_slips'
                ):
                    self.shutdown_gracefully()

                # Sleep some time to do routine checks
                time.sleep(sleep_time)
                slips_internal_time = (
                    float(__database__.getSlipsInternalTime()) + 1
                )
                # Get the amount of modified profiles since we last checked
                (
                    modified_profiles,
                    last_modified_tw_time,
                ) = __database__.getModifiedProfilesSince(
                    slips_internal_time
                )
                amount_of_modified = len(modified_profiles)
                # Get the time of last modified timewindow and set it as a new
                if last_modified_tw_time != 0:
                    __database__.setSlipsInternalTime(
                        last_modified_tw_time
                    )
                # How many profiles we have?
                profilesLen = str(__database__.getProfilesLen())
                if self.mode != 'daemonized' and self.input_type != 'stdin':
                    now = utils.convert_format(datetime.now(), utils.alerts_format)
                    print(
                        f'Total Number of Profiles in DB so '
                        f'far: {profilesLen}. '
                        f'Modified Profiles in the last TW: {amount_of_modified}. '
                        f'({now})',
                        end='\r',
                    )

                # Check if we need to close some TW
                __database__.check_TW_to_close()

                # In interface we keep track of the host IP. If there was no
                # modified TWs in the host NotIP, we check if the network was changed.
                # Don't try to stop slips if it's capturing from an interface
                if self.args.interface:
                    # To check of there was a modified TW in the host IP. If not,
                    # count down.
                    modifiedTW_hostIP = False
                    for profileIP in modified_profiles:
                        # True if there was a modified TW in the host IP
                        if hostIP == profileIP:
                            modifiedTW_hostIP = True

                    # If there was no modified TW in the host IP
                    # then start counting down
                    # After count down we update the host IP, to check if the
                    # network was changed
                    if not modifiedTW_hostIP and self.args.interface:
                        if intervals_to_wait == 0:
                            hostIP = self.get_host_ip()
                            if hostIP:
                                __database__.set_host_ip(hostIP)
                            intervals_to_wait = max_intervals_to_wait

                        intervals_to_wait -= 1
                    else:
                        intervals_to_wait = max_intervals_to_wait


                # Running Slips in the file.
                # If there were no modified TW in the last timewindow time,
                # then start counting down
                else:
                    # don't shutdown slips if it's being debugged or reading flows from stdin
                    if (
                        amount_of_modified == 0
                        and not self.is_debugger_active()
                        and self.input_type != 'stdin'
                    ):
                        # print('Counter to stop Slips. Amount of modified
                        # timewindows: {}. Stop counter: {}'.format(amount_of_modified, minimum_intervals_to_wait))
                        if intervals_to_wait == 0:
                            self.shutdown_gracefully()
                            break
                        intervals_to_wait -= 1
                    else:
                        intervals_to_wait = (
                            max_intervals_to_wait
                        )

                __database__.pubsub.check_health()
        except KeyboardInterrupt:
            # the EINTR error code happens if a signal occurred while the system call was in progress
            # comes here if zeek terminates while slips is still working
            self.shutdown_gracefully()


####################
# Main
####################
if __name__ == '__main__':
    slips = Main()
    if slips.args.stopdaemon:
        # -S is provided
        daemon = Daemon(slips)
        if not daemon.pid:
            # pidfile doesn't exist
            print(
                f"Trying to stop Slips daemon.\n"
                f"Daemon is not running."
            )
        else:
            daemon.stop()
            # it takes about 5 seconds for the stop_slips msg to arrive in the channel, so give slips time to stop
            time.sleep(3)
            print('Daemon stopped.')
    elif slips.args.daemon:
        daemon = Daemon(slips)
        if daemon.pid != None:
            print(f'pidfile {daemon.pidfile} already exists. Daemon already running?')
        else:
            print('Slips daemon started.')
            daemon.start()
    else:
        # interactive mode
        slips.start()
