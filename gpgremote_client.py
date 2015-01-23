#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" GPG Remote Client Module

    copyright: 2015, Vlad "SATtva" Miller, http://vladmiller.info
    license: GNU GPL, see COPYING for details.

    This module is intended as a drop-in replacement for unprivileged GnuPG
    executable. Its purpose is to grab command line arguments, parse them
    into an internal format, get STDIN, load files data, and tranfer all
    that as a request package to the GPG Remote Server. The server, in
    turn, filters command line arguments of inaproprite input, calls gpg
    with provided data, and returns output (namely, newly created files,
    STDOUT, STDERR, and exit code) back to the client.

    The client reads configuration data (specifically, server listening
    host:port) from gpgremote_client.conf file located in ~/.gnupg
    directory unless path is overridden with GNUPGHOME environment
    variable.

    See README for additional details.
"""

import sys, os, json, io, socket


__version__ = '0.9b2'
MIN_PYTHON = (3, 2)
CONFIG = {
    'host': 'localhost',
    'port': 29797,
    'conn_timeout': 60}
CONF_NAME = 'gpgremote_client.conf'
PACKAGE_ERROR = 'error'
PACKAGE_GPG = 'gpg'
OUTPUT_OPTS = ['-o', '--output']
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


class FileSystemError(GPGRemoteException):
    pass


class ResponseError(GPGRemoteException):
    pass


##########################
# Common functions begin #
##########################

# This section is identical for both client and server but duplicated
# in order to keep modules self-contained.

def update_config(path, silent=True):
    """ Update application configuration from the conf file (if exists).

        The function attempts to read the conf file at provided path, and
        update CONFIG dict with its parsed contents. The format for the
        configuration file is "key = value" for str value, or "key" for
        bool values; blank lines and lines starting with hash sign are
        ignored.

        Args:
            path (str): Configuration file pathname.
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
                CONFIG[key.strip()] = value.strip() if separator else True
    except:
        if silent:
            return
        else:
            raise ValueError


def pack(identifier, *fields, files=None):
    """ Prepare package for sending.

        Args:
            identifier (str): Package type identifier.
            *fields: Data fields to include in the package. Data types
                must be JSON-compatible.
            files (dict): Mapping of files binary data to filenames.

        Returns:
            (tuple) Package ready for transmission: its length (int) and
                its contents as a binary stream (io.BytesIO).

        The package is a structure of the following format:

        header|JSON(identifier, fields, files_meta)|binary,

        where header is a 64-bit (8 bytes) JSON packet length header, and
        binary is a concatenated binary data of all included files.
        Filename and size of each file is included in the last item of JSON
        packet as a list of (filename, file size) 2-tuples.
    """
    length = 0
    output = io.BytesIO()
    files = files or {}

    files_meta = [(name, len(data)) for name, data in files.items()]
    package = json.dumps([identifier, fields, files_meta],
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


def unpack(package):
    """ Unpack received package.

        Args:
            package (io.BytesIO): Received package stream.

        Returns:
            (tuple) Package type identifier (str), packed fields (list),
                and {filename: binary_data} mapping (dict).

        Raises:
            PackageError: In case of malformed package.
    """
    try:
        length = int.from_bytes(package.read(HEADER_LEN), 'big')
        identifier, fields, files_meta = json.loads(
                                            package.read(length).decode())
        files = {filename: package.read(length)
                 for filename, length in files_meta}
        return identifier, fields, files
    except:
        raise PackageError


def send(length, data, conn, _override_length=None):
    """ Send binary data over a socket connection.

        The stream is prefixed with 64-bit (8 bytes) data length header.

        Args:
            length (int): Stream length.
            data (io.BytesIO): Data to be sent.
            conn (socket.socket): Connection instance.
            _override_length (int): Use for debugging only.

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


def parse_options(argv):
    """ Parse arguments list.

        Args:
            argv (list): Command line arguments with application name
                excluded (e.g. sys.argv[1:]).

        Returns:
            (list) Arguments are restructured into a list of two-tuples
                of (option, parameter); None as the second element means no
                parameters were provided for an option. Shortened options,
                if given in chained form (multiple options following a
                single dash sign), are separated in distinct elements. The
                trailing command line arguments are assigned to the last
                list elements with None instead of an option name.
    """
    output = []
    trailing_args = []

    args_only = False
    opt_name = None
    for arg in argv:
        # All the following are arguments only.
        if arg == '--':
            args_only = True
            opt_name = None
            continue

        # Trailing argument.
        if args_only:
            trailing_args.append(arg)
        else:
            # An option.
            if arg.startswith('-') and len(arg) > 1:
                # Remove non-POSIX arguments if those were provided.
                if trailing_args:
                    trailing_args = []

                # Split shortened options.
                if not arg.startswith('--') and len(arg) > 2:
                    short_args = ['-' + short for short
                                  in list(arg.lstrip('-'))]
                    opt_name = short_args[-1]
                    for short_arg in short_args:
                        output.append((short_arg, None))
                else:
                    opt_name = arg
                    output.append((opt_name, None))
            # Argument.
            elif opt_name is None or output[-1][1] is not None:
                trailing_args.append(arg)
            # Option parameter.
            else:
                output[-1] = (opt_name, arg)

    return output + [(None, arg) for arg in trailing_args]


def get_filenames(args):
    """ Get filenames of existing files provided in command line arguments.

        Output file(s) (given as -o option parameter) is explicitly
        ignored.

        Args:
            args (list): Parsed command line arguments (output of
                parse_options() function).

        Returns:
            (list) Filenames of existing files.
    """
    return [param for opt, param in args
            if opt not in OUTPUT_OPTS
            and param and os.path.isfile(param)]


def send_request_gpg(args, stdin, filenames, conn):
    """ Generate and send request package for GPG execution.

        Args:
            args (list): Parsed command line arguments (output of
                parse_options() function).
            stdin (bytes): STDIN data.
            filenames (list): Filenames of existing files in command line
                arguments (as per get_filenames() function).
            conn (socket.socket): Connection instance.

        Raises:
            FileSystemError: In case of errors from the file system layer
                during files packing. The filename is passed as the first
                argument.
            TransmissionError: Passed unhandled from the lower level.
            socket.timeout: Passed unhandled from the lower level.
    """
    files = {}
    for filename in filenames:
        try:
            with open(filename, 'rb') as file:
                files[filename] = file.read()
        except:
            raise FileSystemError(filename)

    # Adding STDIN binary stream as None-keyed file.
    if stdin is not None:
        files[None] = stdin

    length, package = pack(PACKAGE_GPG, *args, files=files)
    send(length, package, conn)


def handle_response_gpg(*data):
    """ Process 'gpg' type response package.

        Args:
            data (list): Package contents returned by unpack() with
                identifier element discarded. Packed fields are assumed
                to be a list of [stderr, exit_code]. All GPG-generated
                files are passed as the corresponding data element (see
                unpack() for details) with the None-keyed element being
                STDOUT binary stream. Files are written to the specified
                filenames.

        Raises:
            ResponseError: In case of malformed package.
            FileSystemError: In case any output file cannot be written.
                File name is passed as exception's first argument.
    """
    try:
        fields, files = data
        stderr, exit_code = fields

        # Writing output files. At the very least STDOUT should be
        # contained here.
        try:
            for filename, data in files.items():
                if filename is not None:
                    with open(filename, 'wb') as file:
                        file.write(data)
                else:
                    stdout = data
        except:
            raise FileSystemError(filename)
        # Writing STDERR/STDOUT, sending exit code.
        sys.stderr.write(stderr)
        sys.stdout.buffer.write(stdout)
        sys.exit(exit_code)
    except (TypeError, ValueError):
        raise ResponseError


def handle_response_error(*data):
    """ Process 'error' type response package.

        Args:
            data (list): Package contents returned by unpack() with
                identifier element discarded. Packed fields are assumed
                to be a list of [message, exit_code].

        Raises:
            ResponseError: In case of malformed package.
    """
    try:
        fields, _ = data
        message, code = fields
        error_exit(message, code)
    except (TypeError, ValueError):
        raise ResponseError


def error_exit(msg, code=1):
    """Print error message and send exit code."""
    print(msg)
    sys.exit(code)


if __name__ == '__main__':
    if sys.version_info[:2] < MIN_PYTHON:
        error_exit("Python interpreter version {} or higher is required".
                   format('.'.join([str(i) for i in MIN_PYTHON])))

    # Default conf file is ~/.gnupg/gpgremote_client.conf. Directory can be
    # overridden with GNUPGHOME environment variable.
    conf_path = os.path.join(os.getenv('GNUPGHOME', '~/.gnupg'), CONF_NAME)
    update_config(conf_path)

    args = parse_options(sys.argv[1:])
    stdin = sys.stdin.buffer.read() if not sys.stdin.isatty() else None
    filenames = get_filenames(args)

    try:
        conn = socket.create_connection(
                                (CONFIG['host'], int(CONFIG['port'])),
                                timeout=float(CONFIG['conn_timeout'] or 1))

        # Sending request to the server.
        try:
            send_request_gpg(args, stdin, filenames, conn)
        except (FileSystemError, TransmissionError,
                socket.timeout, BrokenPipeError,
                ConnectionResetError) as exc:
            if isinstance(exc, FileSystemError):
                error_exit("Unable to access or read file '{}'".
                           format(exc.args[1]))
            elif isinstance(exc, (TransmissionError, ConnectionResetError)):
                error_exit('Server has abruptly terminated connection')
            elif isinstance(exc, socket.timeout):
                error_exit('Timed out while sending request to GPG Remote')
            elif isinstance(exc, BrokenPipeError):
                # Optimistically ignore exception to later read from
                # socket as server may have sent a reason for connection
                # termination.
                pass

        # Receiving response from the server.
        try:
            identifier, *response = unpack(receive(conn))
            handle_response = globals()['handle_response_' +
                                        identifier]
            handle_response(*response)
        except (NameError, ResponseError, PackageError,
                TypeError, ValueError, socket.timeout,
                BrokenPipeError, TransmissionError,
                ConnectionResetError, FileSystemError) as exc:
            if isinstance(exc, NameError):
                error_exit('Unknown type response received from '
                           'GPG Remote Server')
            elif isinstance(exc, (ResponseError, PackageError)):
                error_exit('Malformed response received from '
                           'GPG Remote Server')
            elif isinstance(exc, (TypeError, ValueError)):
                error_exit('Unable to unpack GPG Remote Server response')
            elif isinstance(exc, socket.timeout):
                error_exit('Timed out while awaiting response from '
                           'GPG Remote')
            elif isinstance(exc, (BrokenPipeError, TransmissionError,
                                  ConnectionResetError)):
                error_exit('Server has abruptly terminated connection')
            elif isinstance(exc, FileSystemError):
                error_exit("Unable to write file '{}'".format(exc.args[1]))

    except ConnectionRefusedError:
        error_exit('Connection to GPG Remote Server refused. '
                   'Probably no one is listening on the other end')
    finally:
        try:
            conn.close()
        except NameError:
            pass

