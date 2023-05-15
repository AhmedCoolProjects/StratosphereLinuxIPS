from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database.database import __database__
from slips_files.common.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
import sys
import traceback
import socket
import json
import os
import errno

class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'CYST'
    description = 'Communicates with CYST simulation framework'
    authors = ['Alya Gomaa']

    def __init__(self, outputqueue, redis_port):
        multiprocessing.Process.__init__(self)
        self.port = None
        self.outputqueue = outputqueue
        __database__.start(redis_port)
        self.c1 = __database__.subscribe('new_alert')
        self.cyst_UDS = '/run/slips.sock'
        self.conn_closed = False

    def initialize_unix_socket(self):
        """
        If the socket is there, slips will connect to itm if not, slips will create it
        """
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if os.path.exists(self.cyst_UDS):
            os.unlink(self.cyst_UDS)
        # Create a UDS socket
        sock.bind(self.cyst_UDS)
        failure = sock.listen(2)
        if not failure:
            self.print(f"Slips is now listening. waiting for CYST to connect.")
        else:
            error = (f" failed to initialize sips socket. Error code: {failure}")
            return False, error

        connection, client_address = sock.accept()
        return sock, connection


    def get_flow(self):
        """
        reads 1 flow from the CYST socket and converts it to dict
        returns a dict if the flow was received or False if there was an error
        """
        try:
            self.cyst_conn.settimeout(5)
            # get the number of bytes cyst is going to send, it is exactly 5 bytes
            flow_len = self.cyst_conn.recv(5).decode()
            try:
                flow_len: int = int(flow_len)
            except ValueError:
                self.print(f"Received invalid flow length from cyst: {flow_len}")
                self.conn_closed = True
                return False

            flow: bytes = self.cyst_conn.recv(flow_len).decode()

        except socket.timeout:
            self.print("timeout but still listening for flows.")
            return False
        except socket.error as e:
            err = e.args[0]
            if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
                # cyst didn't send anything
                return False
            else:
                self.print(f"An error occurred: {e}")
                self.conn_closed = True
                return False

        # When a recv returns 0 bytes, it means the other side has closed
        # (or is in the process of closing) the connection.
        if not flow:
            self.print(f"CYST closed the connection.")
            self.conn_closed = True
            return False
        try:
            flow = json.loads(flow)
            return flow
        except json.decoder.JSONDecodeError:
            self.print(f'Invalid json line received from CYST. {flow}', 0, 1)
            return False

    def send_length(self, msg: bytes):
        """
        takes care of sending the msg length with padding before the actual msg
        """
        # self.print("Sending evidence length to cyst.")

        # send the length of the msg to cyst first
        msg_len = str(len(msg)).encode()
        # pad the length so it takes exactly 5 bytes, this is what cyst expects
        msg_len += (5- len(msg_len) ) *b' '

        self.cyst_conn.sendall(msg_len)

    def send_alert(self, alert_ID: str, ip_to_block: str):
        """
        Sends the alert ID and the IDs of the evidence causing this alert to cyst
        """
        alert_to_send = {
            'slips_msg_type': 'alert',
            'alert_ID': alert_ID,
            'ip_to_block': ip_to_block
        }
        alert_to_send: bytes = json.dumps(alert_to_send).encode()
        self.send_length(alert_to_send)

        try:
            self.cyst_conn.sendall(alert_to_send)
        except BrokenPipeError:
            self.conn_closed = True
            return

    def close_connection(self):
        print(f"@@@@@@@@@@@@@@@@@@  close conn is called!! ")
        if hasattr(self, 'sock'):
            self.sock.close()
        # delete the socket
        os.unlink(self.cyst_UDS)

    def shutdown_gracefully(self):
        self.close_connection()
        # Confirm that the module is done processing
        __database__.publish('finished_modules', self.name)
        # if slips is done, slips shouldn't expect more flows or send evidence
        # it should terminate
        __database__.publish('finished_modules', 'stop_slips')
        return

    def run(self):
        if not ('-C' in sys.argv or '--CYST' in sys.argv):
            return
        try:
            # connect to cyst
            self.sock, self.cyst_conn = self.initialize_unix_socket()
        except KeyboardInterrupt:
            self.shutdown_gracefully()
            return True
        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem on initialize_unix_socket() line {exception_line}', 0, 1)
            self.print(traceback.format_exc(), 0, 1)
            return True


        while True:
            try:
                #check for connection before sending
                if self.conn_closed :
                    self.print( 'Connection closed by CYST.', 0, 1)
                    self.shutdown_gracefully()
                    return True

                # RECEIVE FLOWS FROM CYST
                if flow := self.get_flow():
                    # send the flow to inputprocess so slips can process it normally
                    __database__.publish('new_cyst_flow', json.dumps(flow))

                #check for connection before receiving
                if self.conn_closed:
                    self.print( 'Connection closed by CYST.', 0, 1)
                    self.shutdown_gracefully()
                    return True

                msg = __database__.get_message(self.c1)
                if (msg and msg['data'] == 'stop_process'):
                    self.shutdown_gracefully()
                    return True

                if utils.is_msg_intended_for(msg, 'new_alert'):
                    print(f"@@@@@@@@@@@@@@@@@@ cyst module received a new blocking request . sending ... ")
                    alert_info: dict = json.loads(msg['data'])
                    profileid = alert_info['profileid']
                    twid = alert_info['twid']
                    # alert_ID is {profileid}_{twid}_{ID}
                    alert_ID = alert_info['alert_ID']
                    self.send_alert(alert_ID, profileid.split('_')[-1])

            except KeyboardInterrupt:
                self.shutdown_gracefully()
                return True
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on the run() line {exception_line}', 0, 1)
                self.print(traceback.format_exc(), 0, 1)
                return True

