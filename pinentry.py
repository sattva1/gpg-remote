#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" GPG Remote client-server pinentry implementation.

    copyright: 2015, Vlad "SATtva" Miller, http://vladmiller.info
    license: GNU GPL, see COPYING for details.

    Originally developed by W. Trevor King <wking@drexel.edu> for pyassuan
    library package.

    Updated and stripped down for GPG Remote, see PinEntry server_ipc(),
    request_pin(), response_pin() and _handle_GETPIN() methods for details.
    Console interface for passphrase input has been removed as unnecessary
    for GPG Remote purposes.
"""

import importlib, socket, array, signal, base64, logging, traceback

import os as _os
import re as _re
import sys as _sys

from pyassuan import __version__ as __pyassuan_version__
from pyassuan import server as _server
from pyassuan import common as _common
from pyassuan import error as _error


__version__ = '1.0b1'
gpgremote = None  # Module placeholder to make IDE happy.
IPC_TIMEOUT = 1
PACKAGE_PIN = 'pin'
CONN_BUF = 1024


def timeout(signum, frame):
    """Timeout signal. Raises socket.timeout exception."""
    raise socket.timeout


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
    _digit_regexp = _re.compile(r'\d+')

    # from proc(5): pid comm state ppid pgrp session tty_nr tpgid
    _tpgrp_regexp = _re.compile(r'\d+ \(\S+\) . \d+ \d+ \d+ \d+ (\d+)')

    def __init__(self, name='pinentry', strict_options=False,
                 single_request=True, **kwargs):
        self.strings = {}
        self.connection = {}
        self.client_conn = None
        self.gpg_timeout = None
        super(PinEntry, self).__init__(
            name=name, strict_options=strict_options,
            single_request=single_request, **kwargs)
        self.valid_options += ['grab', 'no-grab', 'ttyname',
                               'lc-ctype', 'lc-messages', 'default-ok',
                               'default-cancel', 'default-prompt']

    def reset(self):
        super(PinEntry, self).reset()
        self.strings.clear()
        self.connection.clear()

    def server_ipc(self):
        """ Receive GPG Remote Client socket from the Server.

            IPC communication data is received in PINENTRY_USER_DATA
            environment variable as a colon-delimited string of 5 elements:
            application version, path to IPC socket, GPG timeout value,
            path to gpg-remote server directory and gpg-remote server
            module name (the two last elements are used to import data
            transmission functions from the server module). GPG timeout is
            assigned to 'gpg_timeout' attribute.

            Then listening IPC UNIX socket is created awaiting connection
            from the Server. Finally, the client socket descriptor received
            over IPC connection is used to recreate socket instance as
            'client_conn' object attribute (if client socket can't be
            recreated for some reason, this attribute remains None).
        """
        logging.info('Starting IPC')
        ipc_data = _os.getenv('PINENTRY_USER_DATA')

        try:
            if not ipc_data:
                logging.error('No IPC connection data in environment')
                return
            version, socket_file, gpg_timeout, module_dir, module_name = \
                                                        ipc_data.split(':')
            if version != __version__:
                logging.error('IPC version mismatch: server {}, '
                              'pinentry {}'.format(version, __version__))
                return

            self.gpg_timeout = int(gpg_timeout)

            # Importing comm protocol functions.
            _sys.path.insert(0, module_dir)
            global gpgremote
            gpgremote = importlib.import_module(module_name)
            del _sys.path[0]
            logging.debug('gpgremote module imported')

            # Creating IPC listening socket.
            signal.signal(signal.SIGALRM, timeout)
            signal.alarm(IPC_TIMEOUT)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(socket_file)
            sock.listen(1)
            logging.debug('IPC socket created, awaiting connection')
            conn, _ = sock.accept()
            signal.alarm(0)

            # Receiving client socket over IPC connection.
            fds = array.array('i')
            ancbufsize = socket.CMSG_LEN(1 * fds.itemsize)
            _, ancdata, _, _ = conn.recvmsg(CONN_BUF, ancbufsize)
            if not ancdata:
                logging.error('No IPC data received')
                return
            _, _, cmsg_data = ancdata[0]
            fds.fromstring(cmsg_data[:len(cmsg_data) - \
                                     (len(cmsg_data) % fds.itemsize)])
            self.client_conn = socket.fromfd(list(fds)[0], socket.AF_INET,
                                             socket.SOCK_STREAM)
            logging.info('Client socket descriptor received')

        except:
            logging.error('Error receiving IPC data')
        finally:
            try:
                logging.debug('Closing IPC connection')
                conn.close()
                sock.close()
                _os.remove(socket_file)
            except:
                pass

    def request_pin(self):
        """ Send passphrase request to the client along with pinentry
        options and strings data.

            Returns:
                (bool) Operation result: True -- request sent successfully,
                    False -- client connection is missing.
        """
        if not self.client_conn:
            return False
        get_opt = lambda opt: '{} {}'.format(opt[0], opt[1]) \
                            if opt[1] is not None else opt[0]
        strings = [item for item in self.strings.items()]
        options = [('OPTION', get_opt(opt)) for opt in self.options.items()]
        length, package = gpgremote.pack(PACKAGE_PIN, strings, options)
        gpgremote.send(length, package, self.client_conn)
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
        package = gpgremote.receive(self.client_conn)
        identifier, *data = gpgremote.unpack(package)
        if identifier != PACKAGE_PIN:
            return
        responses, _ = data

        output = []
        for response in responses:
            command, params = response
            if params is not None and command != 'ERR':
                params = base64.b64decode(params.encode())
            output.append((command, params))
        return output

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
            yield _common.Response('D', str(_os.getpid()).encode('ascii'))
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
            logging.info('Sending passphrase request to the client')
            request_sent = self.request_pin()

            if not request_sent:
                yield _common.Response('ERR', '1024 Pinentry is unable to '
                                       'connect to client')

            logging.debug('Passphrase request sent')
            logging.debug('Receiving passphrase response from the client')
            responses = self.response_pin()
            signal.alarm(0)
            logging.info('Client response received')

            if not responses:
                yield _common.Response('ERR', '168 Protocol violation')

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
    # Uncomment the next block to enable debug logging.
    # DO NOT USE IN PRODUCTION ENVIRONMENT!
#    log_output = '/tmp/pinentry.log'
#    logging.basicConfig(format='{asctime} {levelname}: Pinentry-' +
#                        str(_os.getpid()) + ': {message}',
#                        filename=log_output,
#                        level=logging.DEBUG,
#                        style='{')

    p = PinEntry()
    logging.info('Started')

    try:
        p.run()
    except:
        p.logger.error(
            'Exiting due to exception:\n{}'.format(
                traceback.format_exc().rstrip()))
        raise
