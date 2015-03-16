#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" GPG Remote Server Module

    copyright: 2015, Vlad "SATtva" Miller, http://vladmiller.info
    license: GNU GPL, see COPYING for details.

    This is a counterpart module for the GPG Remote Client, a threaded
    queued server. Its task is to wait for client request, save received
    files in the temporary location, filter client's command line arguments
    of inapropriate options, and call gpg. Once gpg process has terminated,
    the server collents all generated files and sends them back to the
    client along with other output from gpg invocation.

    By default server reads its configuration from gpgremote_server.conf
    file located in ~/.gnupg (the path can be overridden with GNUPGHOME
    environment variable). However, specific path can be provided with
    -c/--config option to server invocation (-h/--help will print all
    available options). Most server parameters can be reconfigured from the
    command line as well.

    The second part of server configuration is gpg options whitelist
    defined in whitelist.conf in the same directory as server config file.
    See whitelist rules specification in the default whitelist.conf file.

    Client connections are not authenticated, and all requests are
    considered untrusted.

    See README for additional details.
"""

import sys, os, getopt, io, json, shlex, logging, tempfile, \
        threading, signal, socket, array, math, weakref
from collections import OrderedDict
from socketserver import TCPServer, UnixStreamServer, \
                        ThreadingMixIn, BaseRequestHandler
from concurrent.futures import ThreadPoolExecutor
from subprocess import Popen, PIPE, DEVNULL, check_output, \
                        TimeoutExpired, CalledProcessError


__version__ = '1.2'
MIN_PYTHON = (3, 3)
CONFIG = OrderedDict({
    'host': 'localhost',
    'port': 29797,
    'conn_timeout': 15,
    'gpg_timeout': 300,
    'threads': 2,
    'queue': 4,
    'size_limit': 2 ** 30 * 1,  # 1 GiB
    'gpg_exec': '/usr/bin/gpg',
    'strict': False,
    'unsafe': False,
    'whitelist_path': os.path.join(os.getenv('GNUPGHOME', '~/.gnupg'),
                                   'whitelist.conf'),
    'config_path': os.path.join(os.getenv('GNUPGHOME', '~/.gnupg'),
                                'gpgremote_server.conf'),
    'tempdir': os.getenv('TEMP', '/tmp'),
    'logfile': '',
    'verbosity': 'info',
    'debug': False})
TEMP_PREFIX = 'gpgremote_'
PANIC_PREFIX = 'panic_'
IPC_SOCKET = 'pinentry.socket'
IPC_POLL = 0.1
IPC_TIMEOUT = 5
IPC_SIZE_LIMIT = 65536  # Bytes.
IPC_KEY_LEN = 128 // 8  # Bytes.
PBKDF2_ITER_DEFAULT = 1000
PBKDF2_ITER_MAX = 2 ** 16
PBKDF2_SALT = 64 // 8  # Bytes.
PBKDF2_LEN = 256 // 8  # Bytes.
PACKAGE_ERROR = 'error'
PACKAGE_GPG = 'gpg'
PACKAGE_INIT = 'init'
PACKAGE_PANIC = 'panic'
PACKAGE_COMMAND = 'command'
OUTPUT_OPTS = ['-o', '--output']
NO_FILES = '[#NO_FILES]'
CONN_BUF = 4096
HEADER_LEN = 8


class GPGRemoteException(Exception):
    pass


class TransmissionError(GPGRemoteException):
    pass


class StreamLenError(GPGRemoteException):
    pass


class PackageError(GPGRemoteException):
    pass


class VersionMismatchError(GPGRemoteException):
    pass


class AuthenticationError(GPGRemoteException):
    pass


class RequestError(GPGRemoteException):
    pass


class RestrictedError(GPGRemoteException):
    pass


class FilePackageError(GPGRemoteException):
    pass


class AmbiguousError(GPGRemoteException):
    pass


class MalformedArgsError(GPGRemoteException):
    pass


class DebugStub(GPGRemoteException):
    pass


def handle_exc():
    return Exception if not CONFIG['debug'] else DebugStub


##########################
# Common functions begin #
##########################

# This section is identical for both client and server but duplicated
# in order to keep modules self-contained.

try:
    # Use Standard Library secure comparison function if available (with
    # Python 3.3+) instead of own implementation.
    from hmac import compare_digest
    secure_compare = compare_digest  # Make IDE happy.
except ImportError:
    def secure_compare(a, b):
        """Constant-time string/bytes comparison. Only reveals information
        about values length, and whether values types and their lengths are
        same/equal."""
        return len(a) == len(b) and isinstance(a, type(b)) \
                and sum([int(a[i] != b[i]) for i in range(len(a))]) < 1


def update_config(path, storage, silent=True):
    """ Update application configuration from the conf file (if exists).

        The function attempts to read the conf file at provided path, and
        update configuration dict with its parsed contents. The format for
        the configuration file is "key = value" for str/int value, or "key"
        for bool values; blank lines and lines starting with hash sign are
        ignored.

        Args:
            path (str): Configuration file pathname.
            storage (dict): Configuration storage to update in-place.
            silent (bool): Supress any errors.

        Raises:
            ValueError: In case of file read/parse errors in non-silent
                mode.
    """
    try:
        with open(path, 'r') as file:
            for line in file.readlines():
                line = line.strip()
                if line.startswith('#') or not line:
                    continue
                key, separator, value = line.partition('=')
                key, value = key.strip(), value.strip()

                if value.isdecimal():
                    storage[key] = int(value)
                else:
                    storage[key] = value if separator else True
    except:
        if silent:
            return
        else:
            raise ValueError


def pack(identifier, *fields, files=None, auth_key=None):
    """ Prepare package for sending.

        Args:
            identifier (str): Package type identifier.
            *fields: Data fields to include in the package. Data types
                must be JSON-compatible.
            files (dict): Mapping of files binary data to filenames.
            auth_key (bytes): Package contents authentication key (not used
                for binary data). Must be bool(auth_key) == True to enable
                authentication.

        Returns:
            (tuple) Package ready for transmission: its length (int) and
                its contents as a binary stream (io.BytesIO).

        The package is a structure of the following format:

        header|JSON([auth, version], identifier, fields, files_meta)|binary,

        where header is a 64-bit (8 bytes) JSON packet length header, and
        binary is a concatenated binary data of all included files.
        Filename and size of each file is included in the last item of JSON
        packet as a list of (filename, file size) 2-tuples.

        Package is authenticated (if auth_key is provided) with HMAC-SHA256
        over JSON-encoded flat list of package content elements except for
        binary data. Auth token is in hex notation.
    """
    length = 0
    output = io.BytesIO()
    files = files or {}
    files_meta = [(name, len(data)) for name, data in files.items()]

    hmac_local = ''
    if auth_key:
        import hashlib, hmac

        contents = json.dumps([__version__, identifier, fields, files_meta])
        hmac_local = hmac.new(auth_key, contents.encode(),
                              hashlib.sha256).hexdigest()

    header = [hmac_local, __version__]
    package = json.dumps([header, identifier, fields, files_meta],
                         ensure_ascii=False, separators=(',', ':')).encode()

    # Writing header.
    length += output.write(int.to_bytes(len(package), HEADER_LEN, 'big'))
    # Writing JSON packet.
    length += output.write(package)
    # Writing files binary data.
    for name, data in files.items():
        length += output.write(data)
        files[name] = b''  # Trimming to keep memory reqs in bounds.

    output.seek(0)
    return length, output


def unpack(package, auth_key=None):
    """ Unpack received package.

        Args:
            package (io.BytesIO): Received package stream.
            auth_key (bytes): Package contents authentication key (not used
                for binary data). Must be bool(auth_key) == True to enable
                authentication.

        Returns:
            (tuple) Package type identifier (str), packed fields (list),
                and {filename: binary_data} mapping (dict).

        Raises:
            PackageError: In case of malformed package.
            VersionMismatchError: In case the package was created with a
                different application version. Packer version is passed as
                exception's first argument.
            AuthenticationError: In case of authenticated package
                verification failure.
    """
    try:
        length = int.from_bytes(package.read(HEADER_LEN), 'big')
        header, identifier, fields, files_meta = json.loads(
                                            package.read(length).decode())
        hmac_received, version = header

        if auth_key:
            import hashlib, hmac

            contents = json.dumps([version, identifier, fields, files_meta])
            hmac_local = hmac.new(auth_key, contents.encode(),
                                  hashlib.sha256).hexdigest()
            if not secure_compare(hmac_local, hmac_received):
                raise AuthenticationError

        if version != __version__:
            raise VersionMismatchError

        files = {filename: package.read(length)
                 for filename, length in files_meta}
        return identifier, fields, files

    except Exception as exc:
        if isinstance(exc, (VersionMismatchError, AuthenticationError)):
            raise
        else:
            raise PackageError


def send(length, data, conn, _override_length=None):
    """ Send binary data over a socket connection.

        The stream is prefixed with 64-bit (8 bytes) data length header.

        Args:
            length (int): Stream length.
            data (io.BytesIO): Data to be sent.
            conn (socket.socket): Connection instance.
            _override_length (int): For debugging only.

        Raises:
            TransmissionError: In case of abruptly terminated connection.
            socket.timeout: In case of transmission timeout.
    """
    def send_chunk(_data, offset):
        sent = conn.send(_data.getbuffer()[offset:].tobytes())
        if sent == 0:
            raise TransmissionError
        return sent

    sent_total = 0
    header_sent = False
    header = io.BytesIO(int.to_bytes(_override_length or length,
                                     HEADER_LEN, 'big'))
    length += HEADER_LEN

    while sent_total < length:
        if not header_sent and sent_total >= HEADER_LEN:
            header_sent = True
        sent = send_chunk(header if not header_sent else data,
                          sent_total if not header_sent
                          else sent_total - HEADER_LEN)
        sent_total += sent


def receive(conn, len_limit=None):
    """ Receive binary data over a socket connection.

        Data is read from a stream up to the length defined by the 8-byte
        header regardless of the actual stream length.

        Args:
            conn (socket.socket): Connection instance.
            len_limit (int): Length limit imposed on a stream. None or 0 to
                disable length check.

        Returns:
            (io.BytesIO) Binary stream object with received data contents
                excluding length header.

        Raises:
            TransmissionError: In case of abruptly terminated connection.
            StreamLenError: In case data length defined in the header
                exceeds len_limit. Defined length is passed as exception's
                first argument.
            socket.timeout: In case of transmission timeout.
    """
    def receive_chunk():
        received = conn.recv(CONN_BUF)
        if received == b'':
            raise TransmissionError
        return received

    received_total = 0
    output = io.BytesIO()
    header_received = False
    length = CONN_BUF

    while True:
        if not header_received and received_total >= HEADER_LEN:
            header_received = True
            # Read package length from the header.
            output.seek(0)
            header = output.read(HEADER_LEN)
            length = int.from_bytes(header, 'big')
            # Length limit check, if any.
            if len_limit and length > len_limit:
                raise StreamLenError(length)
            # Reinitialize output stream with its current contents except
            # for the header, and set write pointer to its end.
            output = io.BytesIO(output.read(length))
            output.seek(0, io.SEEK_END)
            length += HEADER_LEN

        if received_total >= length:
            break

        data_left = length - received_total
        received = receive_chunk()
        received_total += len(received)
        # Slice the receive buffer in order to not write its tail
        # (exceeding the package length) on the last iteration.
        output.write(received if not header_received else
                     received[:data_left])

    output.seek(0)
    return output

########################
# Common functions end #
########################


def show_help():
    """Print server command line options and exit."""
    usage = """GPG Remote Server {ver}
Command line options:
    -l, --listen        Server listening address:port
                        (default: {host}:{port})
    -t, --threads       Number of processing threads
                        (default: {threads})
    -q, --queue         Requests queue size (total for all threads), 0 for
                        unlimited
                        (default: {queue})
    -s, --size-limit    Maximum package size allowed (total size of STDIN
                        and all input files, in bytes). Note that maximum
                        memory footprint for each thread may be about twice
                        as high
                        (default: {size})
    -g, --gpg           GPG invocation with additional options
                        (default: {gpg})
    -w, --whitelist     Path to whitelist file
                        (default: {whitelist})
    -c, --config        Path to configuration file
                        (default: {config})
        --temp          Path to temp directory for client's plaintext data
                        (default: {temp})
        --conn-timeout  Data transmission timeout (seconds)
                        (default: {conn_timeout})
        --gpg-timeout   GPG process termination timeout (seconds)
                        (default: {gpg_timeout})
        --strict        Strict mode: prevent GPG invocation if any non-
                        whitelisted option is encountered in command line
                        arguments. Otherwise such options are filtered out
        --unsafe        Skip safety checks on server startup
        --reuse-addr    Reuse already binded listening address:port
        --logfile       Path to log file (log to STDOUT if omitted)
        --gen-token     Prompt for user passphrase and output "panic" token
    -v, --verbosity     Verbosity level: debug, info, error, critical
    -h, --help          Show this help screen
""".format(ver=__version__,
           host=CONFIG['host'],
           port=CONFIG['port'],
           threads=CONFIG['threads'],
           queue=CONFIG['queue'],
           size=CONFIG['size_limit'],
           gpg=CONFIG['gpg_exec'],
           whitelist=CONFIG['whitelist_path'],
           config=CONFIG['config_path'],
           temp=CONFIG['tempdir'],
           conn_timeout=CONFIG['conn_timeout'],
           gpg_timeout=CONFIG['gpg_timeout'])
    print(usage)
    sys.exit(2)


def process_options():
    """Process command line options for server invocation."""
    try:
        shortopts = 'l:t:q:s:g:w:c:v:h'
        longopts = ['listen=', 'threads=', 'queue=', 'size-limit=', 'gpg=',
                    'whitelist=', 'config=', 'logfile=', 'verbosity=',
                    'temp=', 'conn-timeout=', 'gpg-timeout=',
                    'reuse-addr', 'strict', 'unsafe', 'gen-token', 'help']
        opts, args = getopt.getopt(sys.argv[1:], shortopts, longopts)
    except getopt.GetoptError as exc:
        print(exc)
        show_help()

    for opt, param in opts:
        if opt in ('-h', '--help'):
            show_help()
        elif opt == '--gen-token':
            gen_token()
        elif opt in ('-l', '--listen'):
            host, port = param.split(':')
            CONFIG['host'] = host
            CONFIG['port'] = port
        elif opt in ('-t', '--threads'):
            CONFIG['threads'] = int(param)
        elif opt in ('-q', '--queue'):
            CONFIG['queue'] = int(param)
        elif opt in ('-s', '--size-limit'):
            CONFIG['size_limit'] = int(param)
        elif opt in ('-g', '--gpg'):
            CONFIG['gpg_exec'] = param
        elif opt in ('-w', '--whitelist'):
            CONFIG['whitelist_path'] = param
        elif opt == '--strict':
            CONFIG['strict'] = True
        elif opt == '--unsafe':
            CONFIG['unsafe'] = True
        elif opt == '--reuse-addr':
            Server.allow_reuse_address = True
        elif opt == '--temp':
            CONFIG['tempdir'] = param
        elif opt == '--conn-timeout':
            CONFIG['conn_timeout'] = param
        elif opt == '--gpg-timeout':
            CONFIG['gpg_timeout'] = param
        elif opt == '--logfile':
            CONFIG['logfile'] = param
        elif opt in ('-v', '--verbosity'):
            CONFIG['verbosity'] = param
        elif opt in ('-c', '--config'):
            try:
                update_config(param, CONFIG, silent=False)
            except ValueError:
                error_exit('Unable to read or parse configuration '
                           'file "{}"'.format(param))

def gen_token():
    """ Prompt user for a passphrase and [optional] iterations count,
    generate and print PBKDF2 token.

        Token format is a string of colon-delimited Base62-encoded
        elements: iterations count (in bytes representation), salt, hash.
    """
    import time, termios
    try:
        import pbkdf2
    except ImportError:
        error_exit('Python pbkdf2 module not found')

    # Prompting for passphrase with disabled character echo.
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    new = termios.tcgetattr(fd)
    new[3] = new[3] & ~termios.ECHO
    try:
        termios.tcsetattr(fd, termios.TCSADRAIN, new)
        passwd = input('Passphrase: ')
        print()
        passwd_confirm = input('Confirm passphrase: ')
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
        print()

    if passwd != passwd_confirm:
        error_exit('Inputs don\'t match, please try again', code=2)

    iter = input('Iterations ({}): '.format(PBKDF2_ITER_DEFAULT)) \
                                                or str(PBKDF2_ITER_DEFAULT)
    if iter and not (iter.isdecimal() and 0 < int(iter) < PBKDF2_ITER_MAX):
        error_exit('Iterations count must be 0 < i < {}. '
                   'Use none for default'.format(PBKDF2_ITER_MAX), code=2)

    start_time = time.monotonic()
    iter = int(iter)
    salt = os.urandom(PBKDF2_SALT)
    hash = pbkdf2.PBKDF2(passwd, salt, iter).read(PBKDF2_LEN)
    gen_time = time.monotonic() - start_time

    encode_token = AnyBase(strict_len=False).encode
    iter = int.to_bytes(iter, int(math.log(PBKDF2_ITER_MAX, 256)), 'big')
    token = ':'.join([encode_token(element) for element
                      in (iter, salt, hash)])

    print()
    print('Hashing took {} sec'.format(round(gen_time, 2)))
    print('Token:')
    print(token)
    print()
    sys.exit(0)


def get_panic_cmds(config):
    """ Return "panic" commands.

        Args:
            config (dict): Configuration storage.

        Returns:
            (list) List of (name, [token, command]) two-tuples.
    """
    commands = [(name[len(PANIC_PREFIX):], opt.partition(' ')[::2])
                for name, opt in config.items()
                if name.startswith(PANIC_PREFIX)]
    # Stop with error if crypt(3) format token is found.
    if any([val[0].find('$') >= 0 for name, val in commands]):
        error_exit('crypt(3)-format "panic" security token detected in '
                   'server configuration file. Please use --gen-token '
                   'to regenerate security tokens according to the new '
                   'format')
    return commands


def parse_whitelist(lines):
    """ Parse GPG commands line options whitelist.

        Lines not starting with a dash sign are ignored. A single set of
        options per line: a set is either a single option (in long or short
        form), or a space-separated long and short forms (in arbitrary
        order).

        Non dash-prefixed words in a set have special meaning. A bracketed
        word is considered a wildcard parameter turning options in a set
        into parameterized ones. An unbracketed word is a whitelisted
        parameter value, and, as such, options in a set can be passed with
        this parameter only (multiple whitelisted parameters must be
        provided on the same line, quoting/space-escaping is supported).
        If a word is bracketed #NO_FILES, it means no files should be
        expected in arguments list for this options set.

        Args:
            lines (list): Whitelist file lines (e.g. readlines() output).

        Returns:
            (dict) Key: whitelisted option (with dash prefix kept intact).
                Value: two-tuple of bool no_files flag and a list of
                whitelisted parameters (Ellipsis for the wildcard parameter
                whitelist, empty list for non-parameterized option).
    """
    output = {}

    for line in lines:
        if not line.startswith('-'):
            continue

        tokens = shlex.split(line.strip())
        params = [token for token in tokens
                  if not token.startswith('-')]
        parameterized = bool(params) and NO_FILES not in params
        no_files = NO_FILES in params
        param_whitelist = [param for param in params if param != NO_FILES
                           and not (param.startswith('[')
                                    and param.endswith(']'))] \
                        or [...] if parameterized else []

        for opt in tokens:
            if opt not in params:
                output[opt.strip()] = (no_files, param_whitelist)

    return output


def filter_options(args, whitelist, strict=False):
    """ Filter command line options according to the whitelist.

        Args:
            args (list): Parsed command line arguments (output of client's
                parse_options() function).
            whitelist (dict): Command line options whitelist.
            strict (bool): When disabled, restricted command line options
                and their parameters are filtered out from the input, and
                the remaining are returned. Otherwise any restricted option
                raises RestrictedError.

        Returns:
            (list) Command line arguments containing whitelisted
                options and their arguments only. The format remains the
                same as returned by parse_options() except that parameter
                of the last non-parameterized option is moved to trailing
                arguments.

        Raises:
            RestrictedError: If rectricted option is encountered while in
                strict mode. Option-parameter pair is passed as the
                exception's first  argument.
            AmbiguousError: If an ambiguous long option (i.e. shortened to
                a non-unique prefix) has been provided. Option name is
                passed as the exception's first argument.
            MalformedArgsError: Failed sanity checks in args package
                format, e.g. option tokens after trailing arguments. Such
                errors should not occur in format-conformant package.
                Option name is passed as the exception's first argument.
    """
    output = []
    trailing_args = []
    args_only = False

    for i, element in enumerate(args):
        to_whitelist = None
        opt, param = element

        # An option.
        if opt is not None:
            element_str = ' '.join([opt, param or ''])

            # Option in trailing args section? It shouldn't be here.
            if args_only:
                raise MalformedArgsError(element_str)

            # Long-form option.
            if opt.startswith('--'):
                # Check long options for ambiguousness.
                matches = [wl for wl in whitelist if wl.find(opt) >= 0]

                # Not whitelisted.
                if not matches:
                    if strict:
                        raise RestrictedError(element_str)
                    else:
                        continue
                # Ambiguous.
                elif not opt in whitelist and len(matches) > 1:
                    raise AmbiguousError(opt)
                # Whitelisted.
                else:
                    # Unambiguate partial match.
                    if not opt in whitelist:
                        opt = matches[0]

                    to_whitelist = (opt, param)
            # Short-form option.
            else:
                if opt in whitelist:
                    to_whitelist = element
                elif strict:
                    raise RestrictedError(element_str)

            # Whitelisted option pending. In case it's not a parameterized
            # option, and the last one before trailing arguments, lets move
            # its "parameter" to trailing args section.
            #
            # NB: Critical section. An error here might open the server to
            # information leakage attacks.
            if to_whitelist is not None:
                opt, param = to_whitelist
                parameterized = whitelist[opt][1]
                last = (i + 1 == len(args)) or (i + 1 < len(args) and
                                                args[i + 1][0] is None)
                if last and not parameterized and param is not None:
                    output.append((opt, None))
                    trailing_args.append((None, param))
                else:
                    output.append(to_whitelist)
        # Trailing argument.
        else:
            args_only = True
            trailing_args.append(element)

    return output + trailing_args


def filter_parameters(args, whitelist, strict=False):
    """ Filter command line parameters according to the whitelist.

        Args:
            args (list): Parsed and filtered command line arguments (output
                of filter_options() function).
            whitelist (dict): Command line options whitelist.
            strict (bool): When disabled, restricted command line options
                and their parameters are filtered out from the input, and
                the remaining are returned. Otherwise any restricted option
                raises RestrictedError.

        Returns:
            (list) Command line arguments containing whitelisted
                options and their arguments only. The format remains the
                same as returned by parse_options().

        Raises:
            RestrictedError: If rectricted parameter is encountered while
                in strict mode. Option-parameter pair is passed as the
                exception's first  argument.
            MalformedArgsError: Failed sanity checks in args package
                format, e.g. parameter provided for unparameterized option.
                Such errors should not occur in format-conformant package.
                Option name is passed as the exception's first argument.
    """
    output = []

    for element in args:
        opt, param = element

        # Skip trailing arguments.
        if opt is None:
            output.append(element)
            continue

        element_str = ' '.join([opt, param or ''])
        param_whitelist = whitelist[opt][1]
        # Parameter provided for unparameterized option?
        if not param_whitelist and param is not None:
            raise MalformedArgsError(element_str)

        # Skip unparameterized options / wildcard whitelist.
        if not param_whitelist or ... in param_whitelist:
            output.append(element)
            continue

        # Whitelist check
        if param in param_whitelist:
            output.append(element)
        elif strict:
            raise RestrictedError(element_str)

    return output


def get_no_files_flag(args, whitelist):
    """ Return no_files flag if such options where passed in command line
    arguments.

        Args:
            args (list): Parsed and filtered command line arguments (output
                of filter_parameters() function).
            whitelist (dict): Command line options whitelist.

        Returns:
            (bool) No_files flag (see param_whitelist() for details).
    """
    return any([whitelist[opt][0] for opt, param in args
                if opt is not None])


def get_option(args, opt, get_all=False):
    """ Get option value if any.

        Args:
            args (list): Parsed command line arguments (output of client's
                parse_options() function).
            opt (str, list): Option name with dash prefix. Multiple option
                synonyms (short/long form) can be provided as a list.
            get_all (bool): If an option is encountered multiple times in
                the arguments list, only its last instance is returned,
                unless get_all function arg is True -- in this case all
                instances are returned as a list.

        Returns:
            (tuple, list) Option value (str), and its index in the
                arguments list (int). If option wasn't found, both elements
                are None. If get_all arg is True, all instances of option
                value and index are packed in a list.
    """
    if isinstance(opt, str):
        opt = [opt]
    output = [(item[1], i) for i, item in enumerate(args)
              if item[0] in opt]

    if not output:
        return (None, None)
    else:
        return (output[-1][0], output[-1][1]) if not get_all else output


def del_options(args, blacklist):
    """ Remove options and their parameters from arguments list.

        Args:
            args (list): Parsed and filtered command line arguments (output
                of filter_*() function).
            blacklist (list): List of options to remove. Any None value in
                the list will remove all trailing arguments.

        Returns:
            (list) Command line arguments without defined options.
    """
    if not isinstance(blacklist, list):
        blacklist = list(blacklist)
    return [element for element in args if element[0] not in blacklist]


def flatten_args(args):
    """ Convert internal command line arguments format (list of two-tuples)
    to a flat list.

        Args:
            args (list): Parsed command line arguments (output of client's
                parse_options() function).

        Returns:
            (list) Flat list of options, parameters, and trailing args.
    """
    return [item for element in args for item in element
            if item is not None]


def get_keyrings(gpg_argv):
    """ Return a list of default server keyrings.

        The function relies on gpg to get all the keyring filenames by
        calling it with --list-options show-keyring --list-{secret-}keys.
        All lines starting with a slash are assumed to be keyring
        filenames.

        NB: The function is not able to detect filenames of empty keyrings
        as gpg does not shows them in its output.

        Args:
            gpg_argv (list): GPG invocation arguments (including
                executable pathname).

        Returns:
            (list) Pathnames of all non-empty keyrings returned by gpg.

        Raises:
            FileNotFoundError: In case gpg executable does not exist.
    """
    def _get_keyrings(args, keyrings):
        """Call GPG with provided additional args and collect keyring
        pathnames in the keyrings list."""

        try:
            stdout = check_output(gpg_argv + args, stderr=DEVNULL,
                                  universal_newlines=True)
        except CalledProcessError as exc:
            stdout = exc.output
        keyrings.update(set([line for line in stdout.splitlines()
                             if line.startswith('/')]))

    keyrings = set()
    _get_keyrings(['--list-options', 'show-keyring', '--list-keys'],
                  keyrings)
    _get_keyrings(['--list-options', 'show-keyring', '--list-secret-keys'],
                  keyrings)

    return keyrings


def error_exit(message, code=1, log_level=None):
    """Print error message (or log with provided logging method), and
    send exit code. Should be used outside of request handler only (see
    Handler.send_error() for the other case)."""
    if not log_level:
        print(message)
    else:
        log_level(message)
    if code == 1:
        print('Unable to start server')
    print()
    sys.exit(code)


def send_error(conn, message, log_level=None, exit_code=1):
    """ Log an error message and send it back to the client along with exit
    code.

        Args:
            conn (socket.socket): Socket instance.
            message (str): Error message.
            log_level (function): Logging severity level method, e.g.
                logging.error.
            exit_code (int): Exit code to be generated by the client.
    """
    if log_level:
        log(message, log_level)
    message = 'GPG Remote Server: ' + message
    package = pack(PACKAGE_ERROR, message, exit_code)
    send(*package, conn=conn)


def log(message, log_level):
    """ Log a message with thread name included. For the main thread only
    the message text is being logged.

        Args:
            message (str): Message to log.
            log_level (function): Logging severity level method, e.g.
                logging.error.
    """
    thread = threading.current_thread().name
    log_level('{}: {}'.format(thread, message) if thread else message)


class AnyBase(object):
    """ Generate string representation of an integer or a bytes array with
    arbitrary base and provided encoding alphabet.

        The implementation is poorly optimized, has subexponential
        complexity, and should be used for short data only (preferrably,
        less than 2 ** 12 bytes), otherwise processing time is likely to be
        excessive.

        The encoding scheme works as follows. First, if the input data is
        bytes starting with a null-byte, the first byte is replaced with
        armoring value (in order to preserve the bytes array on the next
        step). Then input is converted to integer which is encoded with the
        provided alphabet using modular arithmetics and iterative division
        operations; a marker of leading null-byte (if it were present) is
        prepended to the beginning of an encoded string. At this point the
        encoding string may have varying length depending on the input
        value (e.g. 0x000000 vs 0xffffff). This is dealt with in "strict
        length" mode (the default) by prepending the string with at least
        one more character denoting (by its index value in the encoding
        alphabet) the length of padding required to make the encoded output
        length fixed regardless of input value (for a given input length of
        course); the same character is then used as the actual padding if
        additional padding is required. The encoded output conforms to the
        following format:

        [<p> [p ...]] [n] <e ...>

        where p is the padding value (in "strict length" mode only), n is
        the leading null-byte marker, and e is the encoded data contents.

        Attributes:
            BASE62 (str): Predefined 62 characters long alphanumeric
                alphabet. Inflation ratio is 1.349.
    """

    __null_armor = ord('\x01')
    BASE62 = '0123456789abcdefghijklmnopqrstuvwxyz' \
             'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

    def __init__(self, alphabet=None, strict_len=True, to_int=False):
        """ Constructor.

            Args:
                alphabet (str): Encoding alphabet. An encoded output will
                    be a base-N representation of input data, where N is
                    the length of alphabet. The first character is reserved
                    as a marker for a special case of preserving leading
                    null-bytes of the input. Consequently, an alphabet may
                    not be less than 3 characters long (effectively making
                    a binary coding) when not in "strict length" mode, or
                    6 characters otherwise (due to padding). Base-62 is
                    used by default.
                strict_len (bool): For bytes array input only: encode to
                    a string of fixed length for a given input length
                    regardless of input value. If False, the inflation
                    ratio is slightly lower, but encoded output length may
                    vary by a few characters depending on the input and
                    encoding alphabet used.
                to_int (bool): Output decoded data as integer instead of
                    bytes array.
        """
        alphabet = alphabet or self.BASE62
        self.leading_null = None
        self.to_int = to_int
        self.strict_len = strict_len
        self.alphabet = list(alphabet)
        self.null_marker = self.alphabet.pop(0)
        self.base = len(self.alphabet)

    def _len_encoded(self, length):
        """Return maximum length of encoded string given the input bytes
        array length."""
        return math.ceil(math.log(256 ** length, self.base))

    def _len_decoded(self, length):
        """Return maximum length of decoded bytes array given the encoded
        string length."""
        return math.ceil(math.log(self.base ** length, 256))

    def _bytes_to_int(self, bytes_array):
        """Return an integer representation of the provided bytes array."""
        self.leading_null = bytes_array[0] == 0
        if self.leading_null:
            bytes_array[0] = self.__null_armor
        return int.from_bytes(bytes_array, 'big')

    def _int_to_bytes(self, n, max_len):
        """Return the bytes array represented by an integer. 'max_len'
        argument defines the length of output buffer."""
        output = bytearray(n.to_bytes(max_len, 'big')).lstrip(b'\x00')
        if self.leading_null:
            # Restore the original null-byte.
            output[0] = ord('\x00')
        return bytes(output)

    def _encode_int(self, n, max_len=None):
        """Encode integer into a string. If max_len is provided, strict_len
        mode is assumed, and the output is padded to the given length."""
        # Encoding procedure.
        output = []
        while n:
            output.insert(0, self.alphabet[n % self.base])
            n //= self.base
        # Prepend null-byte marker.
        if self.leading_null:
            output.insert(0, self.null_marker)
        # In "strict length" mode, add length padding.
        if max_len is not None:
            padding_len = max_len - len(output) + 1
            padding = [self.alphabet[padding_len]] * padding_len
            output = padding + output
        return ''.join(output)

    def _decode_str(self, string):
        """Decode string into an integer. Returns a tuple of decoded value
        and the maximum length of decoded payload."""
        self.leading_null = False
        index_table = {char: idx for idx, char in enumerate(self.alphabet)}
        string = list(string)
        # Strip padding.
        if self.strict_len and not self.to_int:
            padding_len = index_table[string[0]]
            string = string[padding_len:]
        # Strip null-byte marker.
        if string[0] == self.null_marker:
            self.leading_null = True
            string = string[1:]
        # Decoding procedure.
        output = 0
        for i, char in enumerate(string[::-1]):
            output += index_table[char] * (self.base ** i)
        return output, self._len_decoded(len(string))

    def encode(self, data):
        """ Encode a input data.

            Args:
                data (int, bytes): Input data.

            Returns:
                (str) Encoded output.

            Raises:
                TypeError: On illegal input type.
        """
        if not isinstance(data, (int, bytes)):
            raise TypeError('value to encode must be int or bytes')
        max_len = None
        if isinstance(data, bytes):
            max_len = self._len_encoded(len(data))
            data = self._bytes_to_int(bytearray(data))
        return self._encode_int(data, max_len if self.strict_len else None)

    def decode(self, encoded):
        """ Decode an encoded string.

            The alphabet and output parameters must be identical to those
            used for encoding operation, otherwise decoding will produce
            wrong result.

            Args:
                encoded (str): Encoded data.

            Returns:
                (bytes, int): Decoded data.

            Raises:
                TypeError: On illegal input type.
        """
        if not isinstance(encoded, str):
            raise TypeError('value to decode must be a string')
        n, max_len = self._decode_str(encoded)
        return self._int_to_bytes(n, max_len) if not self.to_int else n


class IPCServer(UnixStreamServer):
    """ Single-threaded IPC server for GPG Remote Server <> Pinentry
    process communication.

        All not explicitly mentioned attributes have standard meaning from
        socketserver.BaseServer.

        Attributes:
            terminate (bool): Stop server flag. Can be used from request
                handler to signal graceful shutdown.
            auth_key (bytes): IPC session authentication key.
            client_conn (socket.socket): Opened TCP socket instance of a
                client connection.
            panic_rules (dict): "Panic" rules provided to pinentry.
            panic_env (dict): Environment variables for "panic" commands.
            stop (threading.Event): Stop server command trigger.
            main_server (weakref.ref): A weak reference to the main GPG
                Remote server instance.
    """

    timeout = IPC_TIMEOUT

    terminate = False
    auth_key = None
    client_conn = None
    panic_rules = None
    panic_env = None
    stop = None
    main_server = None

    def service_actions(self):
        """Stop server if signalled from request handler."""
        if self.terminate:
            self.shutdown()


class IPCHandler(BaseRequestHandler):
    """ Server <> Pinentry IPC requests handler.

        Error handling and reporting is minimal, IPC server thread can be
        safely crashed in most cases.
    """

    def handle(self):
        """Dispatch IPC request."""
        try:
            identifier, *request = unpack(receive(self.request,
                                                  len_limit=IPC_SIZE_LIMIT),
                                          auth_key=self.server.auth_key)
            handle_request = getattr(self, 'handle_request_' + identifier)
            log('IPC request type received: "{}"'.format(identifier),
                logging.debug)
            handle_request(*request)
        except Exception as exc:
            if isinstance(exc, AttributeError):
                log('Unknown IPC request type received: "{}"'.
                    format(identifier), logging.error)
            elif isinstance(exc, AuthenticationError):
                log('IPC request verification failed', logging.error)

    def handle_request_init(self, *data):
        """ Process 'init' type request package.

            Provides pinentry process with the following data in response:
            client socket descriptor, GPG execution timeout value, "panic"
            options definitions, and environment variables for "panic"
            commands. The actual response consists of two subsequent
            transmissions: the first one, carrying client socket, uses
            socket.sendmsg() method; the second one uses regular GPG Remote
            transmission protocol to transfer the rest of the data.

            Args:
                data (list): Package contents returned by unpack() with
                    identifier element discarded. Package is assumed to be
                    empty and is ignored, as the request is only to signal
                    readiness for init data receiving.
        """
        conn = self.request

        # Sending client socket descriptor. There seems to be no way to
        # authenticate ancillary buffer (it'll be modified by kernel in
        # transit), but at least lets authenticate the source.
        descriptor = [self.server.client_conn.fileno()]
        _, package = pack(PACKAGE_INIT, descriptor[0],
                          auth_key=self.server.auth_key)
        conn.sendmsg([package.read()],
                     [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                       array.array("i", descriptor))])

        # Sending remaining data.
        data = [CONFIG['gpg_timeout'], self.server.panic_rules,
                self.server.panic_env]
        package = pack(PACKAGE_INIT, *data, auth_key=self.server.auth_key)
        send(*package, conn=self.request)

        log('IPC init data sent successfully', logging.debug)

    def handle_request_panic(self, *data):
        """ Process 'panic' type request package.

            Args:
                data (list): Package contents returned by unpack() with
                    identifier element discarded. Package is assumed to
                    contain triggered "panic" rule name and exit code of
                    an executed command.
        """
        fields, _ = data
        name, code = fields
        log('"Panic" rule triggered: {}. Command exited with code {}'.
            format(name, code), logging.critical)

    def handle_request_command(self, *data):
        """ Dispatch IPC command received with 'command' type request
        package.

            Args:
                data (list): Package contents returned by unpack() with
                    identifier element discarded. Package contents consists
                    of triggered "panic" rule name and server IPC command
                    name.
        """
        fields, _ = data
        name, command = fields
        try:
            handle_command = getattr(self, 'handle_command_' +
                                     command.lower())
            log('"Panic" rule triggered: {}. Calling server command: {}'.
                format(name, command), logging.critical)
            handle_command()
        except AttributeError:
            log('Unknown server command received: "{}"'.
                format(command), logging.error)

    @classmethod
    def get_commands(cls):
        """Return a list of defined command names."""
        return [name.rpartition('_')[2].upper() for name in dir(cls)
                if name.startswith('handle_command_')]

    def handle_command_stop(self, *data):
        """Execute STOP command. Send stub error response to the client and
        perform graceful server shutdown."""
        log('Stopping server', logging.info)
        send_error(self.server.client_conn, 'Undefined error')

        self.server.terminate = True
        self.server.stop.set()

        main_server = self.server.main_server()
        main_server.terminate = True
        main_server.socket.close()
        os.kill(main_server.pid, signal.SIGTERM)

    def handle_command_kill(self, *data):
        """Execute KILL command. Send SIGKILL to the server process."""
        log('Terminating server', logging.critical)
        os.kill(self.server.main_server().pid, signal.SIGKILL)


class ThreadingPoolMixIn(ThreadingMixIn):
    """ThreadingMixIn replacement with threads pool support."""

    def process_request(self, request, client_address):
        """Submit request to the concurrency pool and register it in the
        server queue. Unregistering happens in Handler.finish()."""
        self.queue_len += 1
        log('Request registered in the queue', logging.debug)

        self.pool.submit(self.process_request_thread,
                         request, client_address)


class Server(ThreadingPoolMixIn, TCPServer):
    """ GPG Remote forking TCP server which will do all the client gpg
    requests handling stuff.

        All not explicitly mentioned attributes have standard meaning from
        socketserver.BaseServer.

        Attributes:
            terminate (bool): Stop server flag. Can be used from handler
                threads to signal graceful shutdown.
            pool (concurrent.futures.ThreadPoolExecutor): Concurrent
                tasks pool.
            queue_len (int): The number of requests currently registered
                in the server queue.
            pid (int): Server PID.
            gpg_argv (list): Pathname of GPG executable along with default
                command line arguments if necessary.
            panic_rules (dict): "Panic" rules provided to pinentry.
            keyrings (str): Space-separated list of GPG keyring files
                detected by the server.
            whitelist (list): Parsed GPG command line options whitelist.
    """

    allow_reuse_address = False
    timeout = None

    terminate = False
    pool = None
    queue_len = 0
    request_queue_size = 2
    pid = None
    gpg_argv = None
    panic_rules = {}
    keyrings = ''
    whitelist = None

    def verify_request(self, request, client_address):
        """Deny access if requests queue is full."""
        allowed = not self.request_queue_size \
                            or self.queue_len < self.request_queue_size
        if not allowed:
            log('Queue overflow, request handling denied', logging.info)
            message = 'Connection refused. Too many requests'
            send_error(request, message, exit_code=1)

        return allowed

    def service_actions(self):
        """Stop server if signalled from a handler thread."""
        if self.terminate:
            self.shutdown()


class Handler(BaseRequestHandler):
    """ GPG Remote Server requests handler.

        Attributes:
            cwd (tempfile.TemporaryDirectory): Temporary working for
                gpg execution.
            tempdirs (dict): Input filenames mapping to their temporary
                directories storage.
            files_received (int): The number of input files received from
                the client.
            no_files (bool): No filenames in arguments flag. No file data
                may be returned if it's True.
    """

    cwd = None
    tempdirs = None
    files_received = None
    no_files = False

    def send_error(self, *args, **kwargs):
        """A shortcut for send_error() with conn=self.request."""
        send_error(self.request, *args, **kwargs)

    def filter_args(self, args):
        """ Run command line arguments filters and set no_files flag.

            See filter_options(), filter_parameters(), get_no_files_flag()
            for details on arguments, exceptions and returned values.

            Returns:
                (list) Filtered arguments.
        """
        strict = CONFIG['strict']
        filtered_opts = filter_parameters(filter_options(
                                    args, self.server.whitelist, strict),
                                          self.server.whitelist, strict)
        self.no_files = get_no_files_flag(filtered_opts,
                                          self.server.whitelist)

        return filtered_opts

    def replace_args_filepaths(self, args, output_file):
        """ Replace file paths provided in command line arguments with
        temporary filenames.

            Both trailing arguments filenames and output filename are
            replaced. If output filename is '-', it's kept intact to retain
            correct output redirection to STDOUT.

            Args:
                args (list): Parsed and filtered command line arguments.
                output_file (tuple): Output file path and item index (see
                    get_option() for details).

            Returns:
                (list) Parsed command line arguments with original
                    file paths replaced with temporary paths.

            Raises:
                PackageError: In case the amount of trailing arguments does
                    not match the amount of transmitted files.
        """
        # If these does not match, then some filenames will be left
        # unreplaced, which is a potential attack vector.
        trailing_args_total = len([1 for opt, param in args if opt is None])
        if self.files_received != trailing_args_total:
            raise PackageError

        # Replacing output filename.
        output_path, output_idx = output_file
        if output_idx is not None and output_path != '-':
            log('Replacing filepath in option {}: {} -> {}'.
                format(args[output_idx][0], args[output_idx][1],
                       self.tempdirs[output_path][1]), logging.debug)
            args[output_idx] = (args[output_idx][0],
                                self.tempdirs[output_path][1])

        for i, element in enumerate(args):
            opt, param = element
            # Skipping options. We only need trailing arguments.
            if opt is not None:
                continue
            # Filename match. Replacing.
            if param in self.tempdirs:
                log('Replacing filepath in argument: {} -> {}'.
                    format(args[i][1], self.tempdirs[param][1]),
                    logging.debug)
                args[i] = (None, self.tempdirs[param][1])

        return args

    def unpack_files(self, files, output_file):
        """ Save client's input files to temporary location.

            Each file is saved into a separate temp subdirectory under a
            system-wide (or manually defined) temp dir. Temp directory
            names are cached in tempdirs attribute dict in the form
            {orig_filepath: (tempdir_obj, temp_filepath, send_back)}, and
            cleaned up at the end of request handling. The meaning of
            remaining tuple elements in tempdirs cache is: temp_filepath is
            an absolute pathname of a file in the temporary storage, and
            send_back is a bool flag indicating whether this specific file
            should be returned back to client (it is True for output file
            only).

            Output file is handled in the same way except no data is
            written to the temporary directory, just tempdir object and
            temporary file path are cached.

            The total number of received files is stored in files_received
            attribute. Note: Output file doesn't get counted.

            Args:
                files (dict): Files package dict {filename: binary_data}
                    from the client's request.
                output_file (tuple): Output file path and item index (see
                    get_option() for details).

            Raises:
                FilePackageError: In case of erroneous data in the package.
                    A name of the corresponding file is returned as the
                    exception's first argument.
        """
        self.tempdirs = {}
        self.files_received = 0
        files_num = len(files)

        output_path, _ = output_file
        if output_path is not None:
            files[output_path] = None

        try:
            for filename, data in files.items():
                if filename is None:
                    continue
                if not filename:
                    raise FilePackageError('[EMPTY FILENAME]')

                tempdir = tempfile.TemporaryDirectory(dir=CONFIG['tempdir'],
                                                      prefix=TEMP_PREFIX)
                filepath = os.path.join(tempdir.name,
                                        os.path.basename(str(filename)))

                # This is the real file, write out data.
                if data is not None:
                    with open(filepath, 'wb') as file:
                        file.write(data)
                    # Trimming to keep memory reqs in bounds.
                    files[filename] = b''

                    log('Extracted client file "{}" to "{}"'.
                        format(filename, filepath), logging.debug)
                # This is the output file, nothing to write.
                elif filename != '-':
                    log('Output file "{}" will be saved to "{}"'.
                        format(filename, filepath), logging.debug)

                # Caching file metadata.
                self.tempdirs[filename] = (tempdir, filepath, data is None)
        except:
            raise FilePackageError(str(filename))

        self.files_received = files_num

    def pack_files(self):
        """ Collect all newly created files and prepare them for
        transmission.

            Returns:
                (dict) Files binary data to filenames mapping. Filenames
                    correspond to the original paths provided by the
                    client.
        """
        if self.no_files:
            return {}

        output = {}
        for orig_filepath, metadata in self.tempdirs.items():
            tempdir, temp_filepath, send_back = metadata

            filenames = os.listdir(tempdir.name)
            for filename in filenames:
                # Skip the input file if it's not intended to be returned.
                if not send_back \
                        and filename == os.path.basename(temp_filepath):
                    continue
                # Generate filepath matching client's input (i.e.
                # concatenate dirname from the original client's file
                # with the filename of a newly created file).
                dirname = os.path.dirname(orig_filepath)
                new_filepath = os.path.join(dirname, filename)
                # Read file data.
                new_temp_filepath = os.path.join(tempdir.name, filename)
                with open(new_temp_filepath, 'rb') as file:
                    output[new_filepath] = file.read()
                log('Found new file "{}", pass to client as "{}"'.
                    format(new_temp_filepath, new_filepath), logging.debug)

        return output

    def handle_request_gpg(self, *data):
        """ Process 'gpg' type request package.

            Args:
                data (list): Package contents returned by unpack() with
                    identifier element discarded. Packed fields are assumed
                    to be a list of args. Input files are passed as the
                    corresponding data element (see unpack() for details)
                    with the None-keyed element being STDIN binary stream.
                    If there is no such element, then the client hasn't
                    passed anything in STDIN.

            Raises:
                RequestError: In case of malformed package.
        """
        try:
            args, files = data
            # XXX: Make sure stdin contains at least an empty bytestring,
            # or GPG might wait for TTY input indefinitely (no idea why --
            # there is no TTY for the subprocess... probably). Although
            # this behavior should be dealt with in a more appropriate
            # manner.
            stdin = files.pop(None) if None in files else b''

            try:
                log('Received argument tokens: {}'.format(args),
                    logging.debug)
                filtered_args = self.filter_args(args)
                log('Whitelisted argument tokens: {}'.format(filtered_args),
                    logging.debug)

                if self.no_files:
                    log('Assuming no filenames in command line arguments',
                        logging.debug)
                    # NB: A necessary step in order to protect server from
                    # accidental information leakage (e.g. gpg -ao - \
                    # -r attackerKey -e /secret/server/file).
                    safe_args = del_options(filtered_args, OUTPUT_OPTS)
                else:
                    output_file = get_option(filtered_args, OUTPUT_OPTS)
                    log('Defined output file: {}'.format(output_file[0]),
                        logging.debug)

                    self.unpack_files(files, output_file)
                    log('Total files unpacked: {}'.
                        format(self.files_received), logging.debug)

                    safe_args = self.replace_args_filepaths(filtered_args,
                                                            output_file)

                gpg_argv = self.server.gpg_argv + flatten_args(safe_args)
                log('Invoking GPG process with shell tokens: {}'.
                    format(gpg_argv), logging.info)

                # Opportunistically pass socket descriptor to the custom
                # pinentry application. For a standard pinentry this should
                # have no effect as it won't initiate IPC protocol.
                socket_dir = tempfile.mkdtemp(dir=CONFIG['tempdir'],
                                              prefix=TEMP_PREFIX)
                socket_file = os.path.join(socket_dir, IPC_SOCKET)
                os.chmod(socket_dir, 493)  # A.k.a. ugo=rx,u+w, or 0755
                log('Starting IPC server listening on "{}"'.
                    format(socket_file), logging.debug)

                # Instantiating IPC server.
                ipc = IPCServer(socket_file, IPCHandler)
                ipc.client_conn = self.request
                ipc.auth_key = os.urandom(IPC_KEY_LEN)
                ipc.panic_rules = self.server.panic_rules
                ipc.panic_env = {'GPG_REMOTE_PID': str(self.server.pid)}
                ipc.stop = threading.Event()
                ipc.main_server = weakref.ref(self.server)

                # Starting IPC server.
                ipc_thread = threading.Thread(target=ipc.serve_forever,
                                      kwargs={'poll_interval': IPC_POLL})
                ipc_thread.daemon = True
                ipc_thread.start()
                os.chmod(socket_file, 511)  #A.k.a. ugo=rwx, or 0777
                log('IPC thread started as {}'.format(ipc_thread.name),
                    logging.debug)

                # Update environment with pinentry IPC data consisting of
                # the following colon-separated elements: application
                # version, IPC authentication key (Base62-encoded), path to
                # IPC socket, path to gpg-remote server directory,
                # gpg-remote server module name. The two last elements will
                # be used to import data transmission functions from the
                # current module.
                module_path = os.path.split(os.path.abspath(__file__))
                module_dir = module_path[0]
                module_name = os.path.splitext(module_path[1])[0]
                ipc_data = [__version__, AnyBase().encode(ipc.auth_key),
                            socket_file, module_dir, module_name]
                env = os.environ.copy()
                env['PINENTRY_USER_DATA'] = ':'.join(ipc_data)

                # Call gpg.
                with Popen(gpg_argv, stdin=PIPE, stdout=PIPE, stderr=PIPE,
                           cwd=self.cwd.name, env=env) as gpg:
                    if stdin:
                        log('Passing {} bytes to GPG process STDIN'.
                            format(len(stdin)), logging.debug)
                    stdout, stderr = gpg.communicate(stdin,
                                    timeout=float(CONFIG['gpg_timeout']))
                    exit_code = gpg.returncode
                    log('GPG process terminated with exit code {}'.
                        format(exit_code), logging.info)

                # Terminate request handling on STOP command.
                if ipc.stop.is_set():
                    self.request.shutdown(socket.SHUT_RDWR)
                    return

                # Collect new files.
                if self.no_files:
                    # NB: A necessary step in order to protect server from
                    # accidental information leakage (e.g. gpg -ao ~/foo \
                    # -r attackerKey -e /secret/server/file).
                    out_files = {}
                else:
                    out_files = self.pack_files()
                    log('Total new files collected: {}'.
                        format(len(out_files)), logging.debug)

                # Send response.
                out_files[None] = stdout
                package = pack(PACKAGE_GPG,
                               stderr.decode(errors='ignore'),
                               exit_code, files=out_files)
                send(*package, conn=self.request)
                log('Response package sent successfully', logging.debug)

            except handle_exc() as exc:
                if isinstance(exc, RestrictedError):
                    self.send_error('Cannot invoke GPG with restricted '
                                    'option/parameter: {}'.
                                    format(exc.args[0]),
                                    logging.info, exit_code=2)
                elif isinstance(exc, AmbiguousError):
                    self.send_error('Ambiguous option: {}'.
                                    format(exc.args[0]),
                                    logging.debug, exit_code=2)
                elif isinstance(exc, MalformedArgsError):
                    self.send_error('Malformed option: {}'.
                                    format(exc.args[0]),
                                    logging.error, exit_code=2)
                elif isinstance(exc, FilePackageError):
                    self.send_error('Unable to unpack file data: {}'.
                                    format(exc.args[0]),
                                    logging.error, exit_code=2)
                elif isinstance(exc, PackageError):
                    self.send_error('General package error. Probably the '
                                    'amount of files received does not '
                                    'match the expected number',
                                    logging.error)
                elif isinstance(exc, TimeoutExpired):
                    try:
                        gpg.kill()
                    except:
                        pass
                    self.send_error('GPG process timed out', logging.error)
                else:
                    self.send_error('Undefined error', logging.error)
            finally:
                try:
                    if not ipc.terminate:
                        ipc.shutdown()
                        ipc_thread.join(IPC_POLL)
                    os.remove(socket_file)
                    os.rmdir(socket_dir)
                    log('IPC thread stopped', logging.debug)
                except:
                    pass
        except handle_exc() as exc:
            raise RequestError

    def handle(self):
        """Dispatch client's request."""
        try:
            log('Begin request handling', logging.info)
            identifier, *request = unpack(receive(self.request,
                                    len_limit=int(CONFIG['size_limit'])))
            handle_request = getattr(self, 'handle_request_' + identifier)
            log('Package "{}" received'.format(identifier), logging.debug)

            self.cwd = tempfile.TemporaryDirectory(dir=CONFIG['tempdir'],
                                                   prefix=TEMP_PREFIX)
            log('Created GPG working dir "{}"'.format(self.cwd.name),
                logging.debug)

            handle_request(*request)

        except handle_exc() as exc:
            if isinstance(exc, AttributeError):
                self.send_error('Unknown request type received from '
                                'GPG Remote client', logging.error)
            elif isinstance(exc, RequestError):
                self.send_error('Malformed request received from '
                                'GPG Remote client', logging.error)
            elif isinstance(exc, (TypeError, ValueError)):
                self.send_error('Unable to unpack GPG Remote '
                                'client request', logging.error)
            elif isinstance(exc, TransmissionError):
                log('Client has abruptly terminated transmission',
                    logging.error)
            elif isinstance(exc, BrokenPipeError):
                log('Client has broken connection', logging.debug)
            elif isinstance(exc, StreamLenError):
                self.send_error('Input size exceeded (bytes): {} > {}'.
                                format(exc.args[0], CONFIG['size_limit']),
                                logging.info, exit_code=1)
            elif isinstance(exc, VersionMismatchError):
                # This error is logged locally only as sending it back
                # would couse the same error on the other end.
                log('Request version mismatch: server {}, client {}'.
                    format(__version__, exc.args[0]), logging.error)
            else:
                self.send_error('Undefined error', logging.error)
        finally:
            # Properly clean up temporary directory.
            try:
                for tempdir, _, _ in self.tempdirs.values():
                    log('Removing temporary dir "{}"'.format(tempdir.name),
                        logging.debug)
                    tempdir.cleanup()

                log('Removing gpg working dir "{}"'.format(self.cwd.name),
                    logging.debug)
                self.cwd.cleanup()
            except AttributeError:
                pass
            log('End request handling', logging.info)

    def finish(self):
        """Unregister request from the server queue."""
        self.server.queue_len -= 1
        log('Request unregistered from the queue, {} left'.
            format(self.server.queue_len), logging.debug)


if __name__ == '__main__':
    if sys.version_info[:2] < MIN_PYTHON:
        error_exit("Python interpreter version {} or higher is required".
                   format('.'.join([str(i) for i in MIN_PYTHON])))

    # Initialize server configuration: read config file, update config
    # from invocation arguments.
    update_config(CONFIG['config_path'], CONFIG)
    process_options()

    # Initialize logging facility.
    threading.current_thread().name = ''
    log_level = getattr(logging, CONFIG['verbosity'].upper(), None)
    if not isinstance(log_level, int):
        print('invalid verbosity level "{}"'.format(CONFIG['verbosity']))
        show_help()
    logging.basicConfig(format='{asctime} {levelname}: {message}',
                        filename=CONFIG['logfile'],
                        level=log_level,
                        style='{')

    print('Starting GPG Remote server')

    if CONFIG['logfile']:
        print('Logging to file "{}" at level "{}"'.format(CONFIG['logfile'],
                                                    CONFIG['verbosity']))

    whitelist_path = os.path.abspath(os.path.expanduser(
                                                CONFIG['whitelist_path']))
    try:
        with open(whitelist_path, 'r') as file:
            Server.whitelist = parse_whitelist(file.readlines())
            log('Parsed whitelist file "{}"'.format(whitelist_path),
                logging.info)
            log('Total options whitelisted: {}'.
                format(len(Server.whitelist)), logging.debug)
    except:
        error_exit('Unable to read or parse whitelist file "{}"'.
                   format(whitelist_path), log_level=logging.critical)
    del file  # Fix for idiotic pylint warning.

    Server.gpg_argv = shlex.split(CONFIG['gpg_exec'])
    log('Default GPG invocation tokens: {}'.format(Server.gpg_argv),
        logging.debug)

    try:
        keyrings = get_keyrings(Server.gpg_argv)
        Server.keyrings = ' '.join([shlex.quote(file) for file in keyrings])
    except FileNotFoundError:
        error_exit('GPG executable "{}" not found'.
                   format(Server.gpg_argv[0]),
                   log_level=logging.critical)

    if not CONFIG['unsafe']:
        log('GPG keyrings checked for write access: {}'.
            format(', '.join(keyrings) if keyrings else 'none found'),
            logging.info)
        if any([os.access(file, os.W_OK) for file in keyrings]):
            error_exit('The current user has write access to some of GPG '
                       'keyrings. GPG Remote Server cannot protect from '
                       'the client adding keys to the keyring. Either take '
                       'steps to make keyring files read-only, or start '
                       'the server with --unsafe option',
                       log_level=logging.critical)
        else:
            log('Checked keyrings are read-only for the current user. '
                'Note: This check cannot detect empty keyrings. Make sure '
                'no empty keyring files are defined in gpg configuration '
                'or invocation options', logging.info)
    else:
        log('Safety checks disabled', logging.critical)

    if int(CONFIG['queue']) \
                        and int(CONFIG['queue']) < int(CONFIG['threads']):
        error_exit('Queue size value cannot be less the number '
                   'of threads', log_level=logging.critical)

    Server.panic_rules = get_panic_cmds(CONFIG)
    if Server.panic_rules:
        log('"Panic" rules enabled: {}'.
            format(', '.join(['"{}: {}"'.format(name, item[1])
                              for name, item
                              in Server.panic_rules])),
            logging.info)

    log('Strict mode {}'.format('enabled' if CONFIG['strict']
                                else 'disabled'), logging.info)
    log('Connection timeout (sec): {}'.format(CONFIG['conn_timeout']),
        logging.info)
    log('GPG process timeout (sec): {}'.format(CONFIG['gpg_timeout']),
        logging.info)
    log('Package size limit (bytes): {}'.format(CONFIG['size_limit']),
        logging.info)
    log('Threads: {}'.format(CONFIG['threads']), logging.info)
    log('Queue size: {}'.format(CONFIG['queue'] or 'unlimited'),
        logging.info)

    if CONFIG['debug']:
        log('RUNNING IN DEBUG MODE', logging.critical)

    try:
        Server.pool = ThreadPoolExecutor(max_workers=int(CONFIG['threads']))
        Server.request_queue_size = int(CONFIG['queue'])
        Server.timeout = float(CONFIG['conn_timeout'])

        server = Server((CONFIG['host'], int(CONFIG['port'])), Handler)
    except OSError:
        error_exit('Listening address:port already in use',
                   log_level=logging.critical)

    Server.pid = os.getpid()
    log('Server started as PID {}. Listening on {}:{}'.
        format(Server.pid, CONFIG['host'], CONFIG['port']), logging.info)

    try:
        def sigterm_handler(signum, frame):
            raise KeyboardInterrupt

        print('Press Ctrl+C or send SIGTERM to exit')
        signal.signal(signal.SIGTERM, sigterm_handler)
        server.serve_forever()
    except KeyboardInterrupt:
        print('Exiting gracefully')
        server.socket.close()
        server.shutdown()
        log('Server stopped by the user', logging.info)
        print()
