import unittest
import os
import socket
import fcntl
import time

import test_0_compilation

from gradescope_utils.autograder_utils.decorators import weight, number, hide_errors, partial_credit
from utils import ProcessRunner, byte_diff
from random import randbytes


start_port = 8080


class TestSecurity(unittest.TestCase):

    def make_test(self, name, use_ref_server, bad_priv=False, bad_pub=False, bad_mac=False):
        timeout = 0.25

        global start_port
        start_port += 1
        server_port = start_port
        start_port += 1
        client_port = start_port

        # Find dir
        paths_to_check = [
            "/autograder/submission/project/Makefile",
            "/autograder/submission/Makefile"
        ]

        makefile_dir = None
        for path in paths_to_check:
            if os.path.isfile(path):
                makefile_dir = os.path.dirname(path)
                break

        if makefile_dir is None:
            print("Makefile not found. Verify your submission has the correct files.")
            self.fail()

        os.chdir("/autograder/source/keys")
        os.system("./gen_files.bash")

        if bad_priv:
            os.system("mv server_key2.bin server_key.bin")

        if bad_pub:
            os.system("mv ca_public_key2.bin ca_public_key.bin")

        file = randbytes(500)

        r_ref = "/autograder/source/src"
        mac = 'mac' if bad_mac else ''
        if use_ref_server:
            server_runner = ProcessRunner(
                f'{r_ref}/server {server_port} {mac}', file, name + "_refserver.out")
            client_runner = ProcessRunner(
                f'{makefile_dir}/client localhost {client_port}', file, name + "_yourclient.out")
        else:
            server_runner = ProcessRunner(
                f'{makefile_dir}/server {server_port}', file, name + "_yourserver.out")
            client_runner = ProcessRunner(
                f'{r_ref}/client localhost {client_port} {mac}', file, name + "_refclient.out")

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        fcntl.fcntl(s, fcntl.F_SETFL, os.O_NONBLOCK)
        fcntl.fcntl(c, fcntl.F_SETFL, os.O_NONBLOCK)
        c.bind(('localhost', client_port))

        server_runner.run()
        time.sleep(0.05)
        client_runner.run()

        start_time = time.time()
        server_packets = 0
        client_packets = 0
        packets = []

        c_addr = None

        server_stdout = b''
        client_stdout = b''
        while time.time() - start_time < timeout:
            if ((server_runner.process and server_runner.process.poll()) or
                    (client_runner.process and client_runner.process.poll())):
                break

            try:
                packet, _ = s.recvfrom(2000)
                if len(packet) > 13 and packet[13:] not in packets:
                    packets.append(packet[13:])
                    server_packets += 1
                if c_addr:
                    c.sendto(packet, c_addr)
            except BlockingIOError:
                pass

            try:
                packet, c_addr = c.recvfrom(2000)
                if len(packet) > 13 and packet[13:] not in packets:
                    packets.append(packet[13:])
                    client_packets += 1
                s.sendto(packet, ('localhost', server_port))
            except BlockingIOError:
                pass

            if server_runner.process is None or client_runner.process is None:
                continue
            if server_runner.process.stdout is None or client_runner.process.stdout is None:
                continue

            server_output = server_runner.process.stdout.read(2000)
            if server_output:
                server_stdout += server_output

            client_output = client_runner.process.stdout.read(2000)
            if client_output:
                client_stdout += client_output

        if server_runner.process is not None and client_runner.process is not None:
            server_runner.process.kill()
            client_runner.process.kill()
        s.close()
        c.close()


        return (server_packets, client_packets, (server_stdout, client_stdout, file))

    @partial_credit(5)
    @number(1.1)
    @hide_errors()
    def test_client_hello(self, set_score):
        """Handshake: Client Hello"""
        if test_0_compilation.failed:
            self.fail()

        sp, cp, _ = self.make_test(self.test_client_hello.__name__, True)

        if sp >= 1:
            set_score(5)
        elif cp >= 1:
            print("Your Client Hello is in an unrecognized form.")
            set_score(2.5)
        else:
            print("Your client failed to send over a Client Hello.")
            set_score(0)

    @partial_credit(20)
    @number(1.2)
    @hide_errors()
    def test_server_hello(self, set_score):
        """Handshake: Server Hello"""
        if test_0_compilation.failed:
            self.fail()

        sp, cp, _ = self.make_test(self.test_server_hello.__name__, False)

        if cp >= 2:
            set_score(20)
        elif sp >= 1:
            print("Your Server Hello is in an unrecognized form.")
            set_score(10)
        else:
            print("Your server failed to send over a Server Hello.")
            set_score(0)

    @partial_credit(30)
    @number(1.3)
    @hide_errors()
    def test_key_exchange_request(self, set_score):
        """Handshake: Key Exchange Request"""
        if test_0_compilation.failed:
            self.fail()

        sp, cp, _ = self.make_test(
            self.test_key_exchange_request.__name__, True)

        if sp >= 2:
            _, cp2, _ = self.make_test(
                self.test_key_exchange_request.__name__ + "_badcert", True, False, True)
            if cp2 > 1:
                print(
                    "Your Key Exchange Request is valid, but your client fails to verify the certificate correctly.")
                set_score(10)
                return

            _, cp3, _ = self.make_test(
                self.test_key_exchange_request.__name__ + "_badpriv", True, True, False)
            if cp3 > 1:
                print(
                    "Your Key Exchange Request is valid, but your client fails to verify the signed nonce correctly.")
                set_score(20)
                return

            set_score(30)

        elif cp >= 2:
            print("Your Key Exchange Request is in an unrecognized form.")
            set_score(5)
        else:
            print("Your client failed to send over a Key Exchange Request.")
            set_score(0)

    @partial_credit(5)
    @number(1.4)
    @hide_errors()
    def test_finished(self, set_score):
        """Handshake: Finished"""
        if test_0_compilation.failed:
            self.fail()

        sp, cp, _ = self.make_test(self.test_finished.__name__, False)

        if cp >= 3:
            set_score(5)
        elif sp >= 2:
            print("Your Finished message is in an unrecognized form.")
            set_score(2.5)
        else:
            print("Your server failed to send over a Finished message.")
            set_score(0)

    @partial_credit(15)
    @number(1.5)
    @hide_errors()
    def test_encrypt_and_mac_client(self, set_score):
        """Encrypt and MAC: Client"""
        if test_0_compilation.failed:
            self.fail()

        _, _, (server, client, file) = self.make_test(
            self.test_encrypt_and_mac_client.__name__, True, False, False, False)

        score = 0
        if server != file:
            print("Your client didn't encrypt data back to our server correctly.")
            print(
                f"We inputted 500 bytes into your client and we received {len(server)} bytes with a percent difference of {byte_diff(file, server)}%")
        else:
            score += 5

        if client != file:
            print("Your client didn't decrypt data from our server correctly.")
            print(
                f"We sent 500 bytes and your client received {len(client)} bytes with a percent difference of {byte_diff(file, client)}%")
        else:
            score += 5

        if score != 10:
            set_score(score)
            return

        _, _, (_, client, file) = self.make_test(
            self.test_encrypt_and_mac_client.__name__ + "_badmac", True, False, False, True)

        if client != file:
            score += 5
        else:
            print("Your client encryption/decryption scheme is valid, but your client fails to authenticate messages properly.")

        set_score(score)

    @partial_credit(15)
    @number(1.6)
    @hide_errors()
    def test_encrypt_and_mac_server(self, set_score):
        """Encrypt and MAC: Server"""
        if test_0_compilation.failed:
            self.fail()

        _, _, (server, client, file) = self.make_test(
            self.test_encrypt_and_mac_client.__name__, False, False, False, False)

        score = 0
        if server != file:
            print("Your server didn't decrypt data back from our client correctly.")
            print(
                f"We sent 500 bytes your server received {len(server)} bytes with a percent difference of {byte_diff(file, server)}%")
        else:
            score += 5

        if client != file:
            print("Your server didn't encrypt data back to our client correctly.")
            print(
                f"We inputted 500 bytes into your server and we received {len(client)} bytes with a percent difference of {byte_diff(file, client)}%")
        else:
            score += 5

        if score != 10:
            set_score(score)
            return

        _, _, (server, _, file) = self.make_test(
            self.test_encrypt_and_mac_client.__name__ + "_badmac", False, False, False, True)

        if server != file:
            score += 5
        else:
            print("Your server encryption/decryption scheme is valid, but your server fails to authenticate messages properly.")

        set_score(score)
