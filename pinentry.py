#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" GPG Remote client-server pinentry implementation.

    copyright: 2015, Vlad "SATtva" Miller, http://vladmiller.info
    license: GNU GPL, see COPYING for details.

    Originally developed by W. Trevor King <wking@drexel.edu> for pyassuan
    library package.

    Updated and stripped down for GPG Remote. Console interface for
    passphrase input has been removed as unnecessary for GPG Remote
    purposes.
"""

import sys, os, importlib, socket, array, signal, base64, logging, \
                                                subprocess, traceback

from pyassuan import __version__ as __pyassuan_version__
from pyassuan import server as _server
from pyassuan import common as _common
from pyassuan import error as _error


__version__ = '1.3'
IPC_TIMEOUT = 5
IPC_SIZE_LIMIT = 65536  # Bytes.
PBKDF2_LEN = 256 // 8  # Bytes.
PACKAGE_INIT = 'init'
PACKAGE_PANIC = 'panic'
PACKAGE_COMMAND = 'command'
PACKAGE_PIN = 'pin'
PACKAGE_OTP = 'otp'
CONN_BUF = 1024
# Module placeholders to make IDE happy.
pbkdf2 = None
gpgremote = None


def timeout(signum, frame):
    """Timeout signal. Raises socket.timeout exception."""
    raise socket.timeout


def assert_(expr, msg=None):
    """Optimization-safe assert statement replacement."""
    if not expr:
        raise AssertionError(msg)


class PinEntry(_server.AssuanServer):
    """pinentry protocol server

    See ``pinentry-0.8.0/doc/pinentry.texi`` at::

      ftp://ftp.gnupg.org/gcrypt/pinentry/
      http://www.gnupg.org/aegypten/

    for details on the pinentry interface.

    Alternatively, you can just watch the logs and guess ;).  Here's a
    trace when driven by GnuPG 2.0.17 (libgcrypt 1.4.6)::

      S: OK Your orders please
      C: OPTION grab
      S: OK
      C: OPTION ttyname=/dev/pts/6
      S: OK
      C: OPTION ttytype=xterm
      S: OK
      C: OPTION lc-ctype=en_US.UTF-8
      S: OK
      C: OPTION lc-messages=en_US.UTF-8
      S: OK
      C: OPTION default-ok=_OK
      S: OK
      C: OPTION default-cancel=_Cancel
      S: OK
      C: OPTION default-prompt=PIN:
      S: OK
      C: OPTION touch-file=/tmp/gpg-7lElMX/S.gpg-agent
      S: OK
      C: GETINFO pid
      S: D 14309
      S: OK
      C: SETDESC Enter passphrase%0A
      S: OK
      C: SETPROMPT Passphrase
      S: OK
      C: GETPIN
      S: D testing!
      S: OK
      C: BYE
      S: OK closing connection
    """

    def __init__(self, name='pinentry', strict_options=False,
                 single_request=True, **kwargs):
        self.strings = {}

        self.auth_key = None
        self.socket_file = None
        self.client_conn = None
        self.gpg_timeout = None
        self.panic_rules = None
        self.panic_env = None
        self.otp = False
        self.otp_expected = (None, None)

        super(PinEntry, self).__init__(
            name=name, strict_options=strict_options,
            single_request=single_request, **kwargs)
        self.valid_options += ['grab', 'no-grab', 'ttyname',
                               'lc-ctype', 'lc-messages', 'default-ok',
                               'default-cancel', 'default-prompt']

    def reset(self):
        super(PinEntry, self).reset()
        self.strings.clear()

    def connect_socket(self):
        """Connect to IPC UNIX socket and return socket instance."""
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(IPC_TIMEOUT)
        conn.connect(self.socket_file)
        return conn

    def server_ipc(self):
        """ Receive GPG Remote Client socket from the Server.

            IPC communication data is received in PINENTRY_USER_DATA
            environment variable as a colon-delimited string of the
            following elements: application version, IPC authentication key
            (Base62-encoded), path to IPC socket, path to gpg-remote server
            directory, gpg-remote server module name (the two last elements
            are used to import data transmission functions from the server
            module).

            Then 'init' type package is sent to the Server; the Server
            responds with two subsequent packages: one containing client
            socket descriptor used to recreate socket instance as
            'client_conn' object attribute (if client socket can't be
            recreated for some reason, this attribute remains None), and
            the other containing remaining data including "panic" rules
            definitions.

            The data transferred over the IPC channel must be authenticated
            with session IPC key.
        """
        logging.info('Starting IPC')
        ipc_data = os.getenv('PINENTRY_USER_DATA').split(':')

        try:
            assert_(ipc_data, 'No IPC connection data in environment')
            assert_(ipc_data[0] == __version__, 'IPC version mismatch: '
                    'server {}, pinentry {}'.format(ipc_data[0],
                                                    __version__))

            _, auth_key, socket_file, module_dir, module_name = ipc_data

            # Importing comm protocol functions.
            sys.path.insert(0, module_dir)
            global gpgremote
            gpgremote = importlib.import_module(module_name)
            del sys.path[0]
            logging.debug('gpgremote module imported')

            # Define connection-related properties.
            self.auth_key = gpgremote.AnyBase().decode(auth_key)
            self.socket_file = socket_file

            conn = self.connect_socket()

            # Connect to IPC server, tell we're ready to receive.
            package = gpgremote.pack(PACKAGE_INIT, None,
                                     auth_key=self.auth_key)
            gpgremote.send(*package, conn=conn)
            logging.debug('IPC init request sent, awaiting response')

            # Receiving and recreating client socket over IPC connection.
            fds = array.array('i')
            ancbufsize = socket.CMSG_LEN(1 * fds.itemsize)
            data, ancdata, _, _ = conn.recvmsg(CONN_BUF, ancbufsize)
            identifier, fields, _ = gpgremote.unpack(
                                                gpgremote.io.BytesIO(data),
                                                self.auth_key)
            assert_(identifier == PACKAGE_INIT)
            _, _, cmsg_data = ancdata[0]
            fds.fromstring(cmsg_data[:len(cmsg_data) -
                                     (len(cmsg_data) % fds.itemsize)])
            self.client_conn = socket.fromfd(list(fds)[0], socket.AF_INET,
                                             socket.SOCK_STREAM)
            logging.info('Client socket descriptor received')

            # Receiving remaining pinentry data.
            data = gpgremote.receive(conn, len_limit=IPC_SIZE_LIMIT)
            identifier, fields, _ = gpgremote.unpack(data, self.auth_key)
            assert_(fields)
            self.gpg_timeout, self.panic_rules, self.panic_env, \
                                                        self.otp = fields
            logging.info('Pinentry application data received')

            conn.close()

            # In case panic rules are defined import pbkdf2 module.
            if self.panic_rules:
                try:
                    global pbkdf2
                    import pbkdf2
                    pbkdf2  # Make IDE happy.
                    logging.debug('pbkdf2 module imported')
                except ImportError:
                    logging.critical('"Panic" commands provided but Python '
                                     'pbkdf2 module not found. Unable to '
                                     'proceed')
                    raise
        except RuntimeError:
            logging.error('Error receiving IPC data')

    def get_otp(self):
        """ Get one-time password from the server.

            Method combines request to the server and response processing.
            Server output is assigned to self.otp_expected attribute as a
            two-tuple of (ID, password).
        """
        conn = self.connect_socket()
        try:
            package = gpgremote.pack(PACKAGE_OTP, None,
                                     auth_key=self.auth_key)
            gpgremote.send(*package, conn=conn)

            data = gpgremote.receive(conn, len_limit=IPC_SIZE_LIMIT)
            identifier, fields, _ = gpgremote.unpack(data, self.auth_key)
            assert_(identifier == PACKAGE_OTP)

            otp = fields[0]
            if otp:
                self.otp_expected = otp
        except:
            pass
        finally:
            conn.close()

    def check_otp(self, passphrase):
        """ Check one-time password.

            Args:
                passphrase (bytes): User-provided passphrase with appended
                    one-time password.

            Returns:
                (bytes) Processed passphrase. The passphrase is either a
                    user-provided one with OTP stripped off (if OTP is
                    valid), or 128 random bytes (if OTP was invalid).
        """
        otp = self.otp_expected[1].encode()
        valid = gpgremote.secure_compare(passphrase[-len(otp):], otp)
        if valid:
            logging.info('OTP correct')
            return passphrase[:-len(otp)]
        else:
            logging.info('OTP incorrect')
            return os.urandom(128)

    def request_pin(self):
        """ Send passphrase request to the client along with pinentry
        options and strings data.

            Returns:
                (bool) Operation result: True -- request sent successfully,
                    False -- client connection is missing.
        """
        if not self.client_conn:
            return False

        if self.otp:
            logging.info('OTP mode enabled, requesting OTP from server')
            self.get_otp()
            logging.info('OTP data: {}'.format(self.otp_expected))

        logging.info('Sending passphrase request to the client')
        get_opt = lambda opt: '{} {}'.format(opt[0], opt[1]) \
                            if opt[1] is not None else opt[0]
        strings = [item for item in self.strings.items()]
        options = [('OPTION', get_opt(opt)) for opt in self.options.items()]
        package = gpgremote.pack(PACKAGE_PIN, strings, options,
                                 self.otp, self.otp_expected[0])
        gpgremote.send(*package, conn=self.client_conn)
        logging.debug('Passphrase request sent')
        return True

    def response_pin(self):
        """ Receive passphrase response from the client.

            The response package is expected to consist of a list of
            pyassuan response two-tuples of the following format:
            (command, data), where data can either be a string literal (for
            ERR type commands), a Base64-encoded payload, or None.

            Returns:
                (list) A list of decoded pyassuan response two-tuples, or
                    None in case of protocol violation.
        """
        logging.debug('Receiving passphrase response from the client')
        # No need to handle oversize condition, just crash the process.
        package = gpgremote.receive(self.client_conn,
                                    len_limit=IPC_SIZE_LIMIT)
        identifier, *data = gpgremote.unpack(package)
        if identifier != PACKAGE_PIN:
            return
        responses, _ = data

        if self.otp and not all(self.otp_expected):
            # Empty OTP list. Simulating 'Cancel' user response.
            logging.info('Simulate "Cancel" due to empty OTP list')
            return [('ERR', '83886179 canceled')]

        output = []
        for command, params in responses:
            if params is not None and command != 'ERR':
                params = base64.b64decode(params.encode())
                # Checking OTP, stripping it off, and sending passphrase
                # along. If OTP is invalid, replacing passphrase with
                # random bytes stub.
                if self.otp and command == 'D':
                    params = self.check_otp(params)
            output.append((command, params))

        logging.info('Client response received')
        return output

    def exec_panic_rules(self, responses):
        """ Execute "panic" rules.

            The function compares user-provided passphrase (if contained in
            the responses list) to "panic" tokens and executes all matched
            commands.
        """
        if not self.panic_rules:
            logging.debug('No "panic" rules specified')
            return

        passwd = None
        for command, data in responses:
            if command == 'D':
                passwd = data
        if passwd is None:
            logging.debug('No user passphrase in response, '
                          'skipping "panic" rules')
            return

        server_commands = gpgremote.IPCHandler.get_commands()
        decode_token = gpgremote.AnyBase(strict_len=False).decode
        cache = {}
        for name, rule in self.panic_rules:
            token, cmd = rule
            cmd = cmd.strip()
            iter, salt, rule_hash = [decode_token(element) for element
                                     in token.strip().split(':')]
            iter = int.from_bytes(iter, 'big')

            # Try to fetch from cache, otherwise generate PBKDF2 hash
            # from the user passphrase and cache it.
            if (iter, salt) in cache:
                logging.debug('Cache hit for rule: {}'.format(name))
                user_hash = cache[(iter, salt)]
            else:
                logging.debug('Cache miss for rule: {}'.format(name))
                user_hash = pbkdf2.PBKDF2(passwd, salt,
                                          iter).read(PBKDF2_LEN)
                cache[(iter, salt)] = user_hash

            # Does the passphrase match?
            if not gpgremote.secure_compare(user_hash, rule_hash):
                continue

            logging.info('Matched "panic" rule: {}'.format(name))
            conn = self.connect_socket()

            if cmd in server_commands:
                # Calling server command.
                logging.info('Call server IPC command: {}'.format(cmd))
                package = gpgremote.pack(PACKAGE_COMMAND, name, cmd,
                                         auth_key=self.auth_key)
                gpgremote.send(*package, conn=conn)
            else:
                # Running shell command.
                env = os.environ.copy()
                env.update(self.panic_env)
                code = subprocess.call(cmd, env=env, shell=True)
                logging.info('Command executed with exit code {}'.
                             format(code))
                # Sending log.
                package = gpgremote.pack(PACKAGE_PANIC, name, code,
                                         auth_key=self.auth_key)
                gpgremote.send(*package, conn=conn)
                logging.debug('Execution log sent')

            conn.close()

    def _connect(self):
        pass

    def _disconnect(self):
        pass

    def _write(self, string):
        pass

    def _read(self):
        return ''

    def _prompt(self, *args, **kwargs):
        return ''

    # assuan handlers

    def _handle_GETINFO(self, arg):
        if arg == 'pid':
            yield _common.Response('D', str(os.getpid()).encode('ascii'))
        elif arg == 'version':
            yield _common.Response('D', __pyassuan_version__.encode('ascii'))
        else:
            raise _error.AssuanError(message='Invalid parameter')
        yield _common.Response('OK')

    def _handle_SETDESC(self, arg):
        self.strings['SETDESC'] = arg
        yield _common.Response('OK')

    def _handle_SETPROMPT(self, arg):
        self.strings['SETPROMPT'] = arg
        yield _common.Response('OK')

    def _handle_SETERROR(self, arg):
        self.strings['SETERROR'] = arg
        yield _common.Response('OK')

    def _handle_SETTITLE(self, arg):
        self.strings['SETTITLE'] = arg
        yield _common.Response('OK')

    def _handle_SETOK(self, arg):
        self.strings['SETOK'] = arg
        yield _common.Response('OK')

    def _handle_SETCANCEL(self, arg):
        self.strings['SETCANCEL'] = arg
        yield _common.Response('OK')

    def _handle_SETNOTOK(self, arg):
        self.strings['SETNOTOK'] = arg
        yield _common.Response('OK')

    def _handle_SETQUALITYBAR(self, arg):
        """Adds a quality indicator to the GETPIN window.

        This indicator is updated as the passphrase is typed.  The
        clients needs to implement an inquiry named "QUALITY" which
        gets passed the current passpharse (percent-plus escaped) and
        should send back a string with a single numerical vauelue
        between -100 and 100.  Negative values will be displayed in
        red.

        If a custom label for the quality bar is required, just add
        that label as an argument as percent escaped string.  You will
        need this feature to translate the label because pinentry has
        no internal gettext except for stock strings from the toolkit
        library.

        If you want to show a tooltip for the quality bar, you may use

            C: SETQUALITYBAR_TT string
            S: OK

        With STRING being a percent escaped string shown as the tooltip.
        """
        raise NotImplementedError()

    def _handle_GETPIN(self, arg):
        try:
            self.server_ipc()
            signal.signal(signal.SIGALRM, timeout)
            signal.alarm(self.gpg_timeout)
            request_sent = self.request_pin()
            if not request_sent:
                yield _common.Response('ERR', '1024 Pinentry is unable to '
                                       'connect to client')
            responses = self.response_pin()
            signal.alarm(0)
            if not responses:
                yield _common.Response('ERR', '168 Protocol violation')

            self.exec_panic_rules(responses)

            for response in responses:
                command, params = response
                yield _common.Response(command, params)

        except socket.timeout:
            yield _common.Response('ERR', '62 Timeout')
        finally:
            self._disconnect()

    def _handle_CONFIRM(self, arg):
        try:
            self._connect()
            self._write(self.strings['SETDESC'])
            self._write('1) '+self.strings['SETOK'])
            self._write('2) '+self.strings['SETNOTOK'])
            value = self._prompt('?')
        finally:
            self._disconnect()
        if value == '1':
            yield _common.Response('OK')
        else:
            raise _error.AssuanError(message='Not confirmed')

    def _handle_MESSAGE(self, arg):
        self._write(self.strings['SETDESC'])
        yield _common.Response('OK')


if __name__ == '__main__':
    p = PinEntry()

    # Uncomment the next block to enable debug logging.
    # DO NOT USE IN PRODUCTION ENVIRONMENT!
#    log_output = '/tmp/pinentry.log'
#    p.logger.setLevel(logging.DEBUG)
#    logging.basicConfig(format='{asctime} {levelname}: Pinentry-' +
#                        str(os.getpid()) + ': {message}',
#                        filename=log_output,
#                        level=logging.DEBUG,
#                        style='{')

    logging.info('Started')

    try:
        p.run()
    except:
        p.logger.error(
            'Exiting due to exception:\n{}'.format(
                traceback.format_exc().rstrip()))
        raise

