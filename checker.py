__author__ = 'Konstantce'
from themis.checker import Server, Result
import socket
import random
import string
import time
import hashlib
import base64
import binascii
import os


class CryptoHelper():
    __small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
                      101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
                      197, 199, 211, 223, 227, 229, 233, 239, 241, 251]
    __count = 25

    def __initial_check(self, number):
        for elem in self.__small_primes:
            if not (number % elem):
                return False
        return True

    def primality_test(self, number):
        #solovay_strassen
        if number in self.__small_primes:
            return True
        if not self.__initial_check(number):
            return False
        for _ in xrange(self.__count):
            a = random.randint(2, number - 1)
            if self.__gcd(a, number) != 1:
                return False
            result = pow(a, (number - 1) / 2, number)
            if (result - self.__jacobi(a, number)) % number:
                return False
        return True

    def __gcd(self, a, b):
        """
        Return greatest common divisor using Euclid's Algorithm.
        """
        if a == 0:
            return b
        if b == 0:
            return a
        while b:
            a, b = b, a % b
        return abs(a)

    def __jacobi(self, a, b):
        """
        Return Jacobi symbol (or Legendre symbol if b is prime)
        """
        degree = 0
        while b > 1:
            if b & 1 == 0:
                raise CryptoError("Jacobi is defined only for odd modules")
            if not a:
                return 0
            elif a < 0:
                a = -a
                degree += (b-1)/2
            a = a % b
            k = 0
            while not a % 2:
                k += 1
                a /= 2
            if k % 2:
                degree += (b*b-1)/8
            degree += (a-1)*(b-1)/4
            a, b = b, a
        if degree % 2:
            return -1
        else:
            return 1

    def elgamal_sign_check(self, p, g, y, r, s, message):
        m = hashlib.sha512()
        m.update(message)
        hash = int("0x" + m.hexdigest(), 0x10) % p
        return (pow(y, r, p)*pow(r, s, p)) % p == pow(g, hash, p)


class CryptoError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)


class SampleChecker(Server):
    SOCKET_TIMEOUT = "SOCKET_TIMEOUT"
    SOCKET_BIND_RANGE_START = "SOCKET_BIND_RANGE_START"
    SOCKET_BIND_RANGE_END = "SOCKET_BIND_RANGE_END"


    PORT = 21
    default_port_range = ["5000", "6000"]
    default_timeout = "5"
    REPL_220 = "220 Service ready for new user.\r\n"
    REPL_331_ANON = "331 Anonymous login okay, send your complete email as your password.\r\n"
    REPL_230 = "230 User logged in, proceed.\r\n"
    REPL_200 = "200 Command okay.\r\n"
    REPL_250 = "250 Requested file action okay, completed.\r\n"
    REPL_221 = "221 Service closing control connection.\r\n"
    REPL_530_NON_ADMIN = "530 This action is allowed only for admin users.\r\n"
    END_MARKER = "\r\n"

    def __init__(self):
        Server.__init__(self)
        self.timeout = int(os.getenv("SOCKET_TIMEOUT", self.default_timeout))
        self.port_range_start = int(os.getenv("SOCKET_BIND_RANGE_START", self.default_port_range[0]))
        self.port_range_end = int(os.getenv("SOCKET_BIND_RANGE_END", self.default_port_range[1]))

    def recv_all(self, sock):
        data = ''
        while True:
            target_data = sock.recv(8192)
            if target_data == '':
                break
            data += target_data
            if self.END_MARKER in data:
                self.logger.debug("Received message: %s", data)
                break
        if data == "":
            raise socket.timeout
        return data

    def send_all(self, sock, mes):
        sock.send(mes)
        self.logger.debug("Sent message: %s", mes)

    def check_reply(self, data, reply='', start='', substr='', end=''):
        if start and not data.startswith(start):
            return False
        if end and not data.endswith(end):
            return False
        if reply and data != reply:
            return False
        if data.find(substr) == -1:
            return False
        return True

    def push(self, endpoint, flag_id, flag):
        try:
            result = self.__push(endpoint, flag_id, flag)
        except (socket.error, socket.timeout):
            self.logger.exception("SOCKET EXCEPTION: SERVICE IS DOWN")
            return Result.DOWN, flag_id
        except ValueError:
            self.logger.exception("INCORRECT STR TO NUMBER CONVERSION: SERVICE IS VIOLATING PROTOCOL")
            return Result.MUMBLE, flag_id
        except CryptoError:
            self.logger.exception("ELGAMAL PARAMETERS ARE INCORRECT: SERVICE IS VIOLATING PROTOCOL")
            return Result.MUMBLE, flag_id
        except:
            self.logger.exception("UNEXPECTED ERROR: INTERNAL ERROR")
            return Result.INTERNAL_ERROR, flag_id
        return result

    def __push(self, endpoint, flag_id, flag):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        #to prevent checker blocking on recv or send
        s.settimeout(self.timeout)
        s.connect((endpoint, self.PORT))
        greeting = self.recv_all(s)
        if not self.check_reply(greeting, reply=self.REPL_220):
                return Result.MUMBLE, flag_id


        self.send_all(s, "USER anonymous")
        reply = self.recv_all(s)
        if not self.check_reply(reply, reply=self.REPL_331_ANON):
            return Result.MUMBLE, flag_id

        password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(6)) + "@gmail.com"
        self.send_all(s, "PASS " + password)
        reply = self.recv_all(s)
        if not self.check_reply(reply, reply=self.REPL_230):
            return Result.MUMBLE, flag_id

        self.send_all(s, "HELP")
        reply = self.recv_all(s)
        if not self.check_reply(reply, start="214-Help message.\n\r", end="214 End Help message.\r\n",
                                substr="This is a tiny and nonstandart FTPserver.\n\r"):
            return Result.MUMBLE, flag_id
        data = reply.split("\n\r")
        p = int("0x" + data[5][2:], 0x10)
        g = int("0x" + data[6][2:], 0x10)
        y = int("0x" + data[7][2:], 0x10)

        #check p for primality, g for being a generator:
        cr_helper = CryptoHelper()
        if not cr_helper.primality_test(p):
            raise CryptoError("p is not prime")
        q = (p-1)/2
        if not cr_helper.primality_test(q):
            raise CryptoError("q is not prime!")
        if pow(g, 2, p) == 1 or pow(g, q, p) == 1 or pow(g, p-1, p) != 1:
            raise CryptoError("g is not a generator!")

        #creating new dir and stepping into it
        dir_name = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(9)) + \
                   "." + time.strftime("%H:%M:%S")
        self.send_all(s, "MKD " + dir_name)
        reply = self.recv_all(s)
        if not self.check_reply(reply, start="257 " + dir_name +
                                " created. To access created item send the following passphrase with ACCT command:"):
            return Result.MUMBLE, flag_id
        dir_acct = reply[reply.rfind(" ")+1: -3]
        #checking sign
        r = int("0x" + dir_acct[:dir_acct.find(":")], 0x10)
        n = int("0x" + dir_acct[dir_acct.find(":")+1:], 0x10)
        if not cr_helper.elgamal_sign_check(p, g, y, r, n, dir_name):
            raise CryptoError("Sign for directory is not correct!")

        self.send_all(s, "ACCT " + dir_acct)
        reply = self.recv_all(s)
        if not self.check_reply(reply, reply=self.REPL_200):
            return Result.MUMBLE, flag_id

        self.send_all(s, "CWD " + dir_name)
        reply = self.recv_all(s)
        if not self.check_reply(reply, reply=self.REPL_250):
            return Result.MUMBLE, flag_id

        self.send_all(s, "PWD")
        reply = self.recv_all(s)
        if not self.check_reply(reply, substr=dir_name, end="is current working dir.\r\n"):
            return Result.MUMBLE, flag_id

        #checking if SITE command is avaliable - against evil patcher teams
        exec_command = ''.join(random.choice(string.ascii_letters) for _ in range(4))
        self.send_all(s, "SITE " + exec_command)
        reply = self.recv_all(s)
        if not self.check_reply(reply, reply=self.REPL_530_NON_ADMIN):
            return Result.MUMBLE, flag_id

        #creating data connection
        addr = s.getsockname()[0]
        port = random.randint(self.port_range_start, self.port_range_end)
        arg = ",".join(addr.split(".")) + "," + str(port / 0x100) + "," + str(port % 0x100)
        self.send_all(s, "PORT " + arg)
        reply = self.recv_all(s)
        if not self.check_reply(reply, reply=self.REPL_200):
            return Result.MUMBLE, flag_id
        data_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        data_conn.bind((addr, port))
        data_conn.listen(1)

        #creating new file with flag
        self.send_all(s, "STOU")
        reply = self.recv_all(s)
        if not self.check_reply(reply, start="151 New file name is:",
                                substr="150 File status okay; about to open data connection."):
            return Result.MUMBLE, flag_id
        data = reply.split("\n\r")
        file_name = data[0][-7: -1]
        conn = data_conn.accept()[0]
        self.send_all(conn, flag)
        conn.close()
        data_conn.close()
        reply = self.recv_all(s)
        if not self.check_reply(reply,
                                start="226 Closing data connection. To access created item send"):
            return Result.MUMBLE, flag_id
        file_acct = reply[reply.rfind(" ")+1: -3]

        #checking filename sign
        r = int("0x" + file_acct[:file_acct.find(":")], 0x10)
        n = int("0x" + file_acct[file_acct.find(":")+1:], 0x10)
        if not cr_helper.elgamal_sign_check(p, g, y, r, n, file_name):
            raise CryptoError("Sign for filename is not correct!")

        #Quiting
        self.send_all(s, "QUIT")
        reply = self.recv_all(s)
        if not self.check_reply(reply, reply=self.REPL_221):
            return Result.MUMBLE, flag_id

        #final encoding
        dir_acct = dir_acct.split(":")
        dir_acct = base64.b64encode(binascii.unhexlify(dir_acct[0])) + ":" + \
                   base64.b64encode(binascii.unhexlify(dir_acct[1]))
        file_acct = file_acct.split(":")
        file_acct = base64.b64encode(binascii.unhexlify(file_acct[0])) + ":" + \
                   base64.b64encode(binascii.unhexlify(file_acct[1]))
        flag_id = dir_name + " " + dir_acct + " " + file_name + " " + file_acct
        s.close()
        return Result.UP, flag_id

    def pull(self, endpoint, flag_id, flag):
        try:
            result = self.__pull(endpoint, flag_id, flag)
        except (socket.error, socket.timeout):
            self.logger.exception("SOCKET EXCEPTION: SERVICE IS DOWN")
            return Result.DOWN
        except:
            self.logger.exception("UNEXPECTED ERROR: INTERNAL ERROR")
            return Result.INTERNAL_ERROR
        return result

    def __pull(self, endpoint, flag_id, flag):
        #encode flag id first
        flag_id = flag_id.split(" ")
        dir_name = flag_id[0]
        dir_acct = flag_id[1].split(":")
        dir_acct = binascii.hexlify(base64.b64decode(dir_acct[0])) + ":" + \
                   binascii.hexlify(base64.b64decode(dir_acct[1]))
        file_name = flag_id[2]
        file_acct = flag_id[3].split(":")
        file_acct = binascii.hexlify(base64.b64decode(file_acct[0])) + ":" + \
                    binascii.hexlify(base64.b64decode(file_acct[1]))

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        #to prevent checker blocking on recv or send
        s.settimeout(self.timeout)
        s.connect((endpoint, self.PORT))

        greeting = self.recv_all(s)
        if not self.check_reply(greeting, reply=self.REPL_220):
                return Result.MUMBLE


        self.send_all(s, "USER anonymous")
        reply = self.recv_all(s)
        if not self.check_reply(reply, reply=self.REPL_331_ANON):
            return Result.MUMBLE

        password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(6)) + "@gmail.com"
        self.send_all(s, "PASS " + password)
        reply = self.recv_all(s)
        if not self.check_reply(reply, reply=self.REPL_230):
            return Result.MUMBLE

        self.send_all(s, "ACCT " + dir_acct)
        reply = self.recv_all(s)
        if not self.check_reply(reply, reply=self.REPL_200):
            return Result.MUMBLE

        self.send_all(s, "CWD " + dir_name)
        reply = self.recv_all(s)
        if not self.check_reply(reply, reply=self.REPL_250):
            return Result.MUMBLE

        self.send_all(s, "PWD")
        reply = self.recv_all(s)
        if not self.check_reply(reply, substr=dir_name, end="is current working dir.\r\n"):
            return Result.MUMBLE

        #creating data connection
        addr = s.getsockname()[0]
        port = random.randint(self.port_range_start, self.port_range_end)
        arg = ",".join(addr.split(".")) + "," + str(port / 0x100) + "," + str(port % 0x100)
        self.send_all(s, "PORT " + arg)
        reply = self.recv_all(s)
        if not self.check_reply(reply, reply=self.REPL_200):
            return Result.MUMBLE
        data_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        data_conn.bind((addr, port))
        data_conn.listen(1)

        self.send_all(s, "ACCT " + file_acct)
        reply = self.recv_all(s)
        if not self.check_reply(reply, reply=self.REPL_200):
            return Result.MUMBLE

        #retrieving previously created file with flag
        self.send_all(s, "RETR " + file_name)
        reply = self.recv_all(s)
        if not self.check_reply(reply, reply="150 File status okay; about to open data connection.\r\n"):
            return Result.MUMBLE
        conn = data_conn.accept()[0]
        saved_flag = conn.recv(1024)
        conn.close()
        data_conn.close()
        if saved_flag != flag:
            return Result.CORRUPT
        reply = self.recv_all(s)
        if not self.check_reply(reply, reply="226 Closing data connection.\r\n"):
            return Result.MUMBLE

        #Quiting
        self.send_all(s, "QUIT")
        reply = self.recv_all(s)
        if not self.check_reply(reply, reply=self.REPL_221):
            return Result.MUMBLE
        return Result.UP


checker = SampleChecker()
#for x in xrange(1):
#    result, flag_id = checker.push("10.1.10.132", "flag_id", "flag_maza_fucka!")
#    print "Push return is", result, " data: ", flag_id + "\n"
#    print "Pulling return is: ", checker.pull("10.1.10.132", flag_id, "flag_maza_fucka!")

checker.run()

