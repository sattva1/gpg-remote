# -*- coding: utf-8 -*-

""" GPG Remote communication testing

    copyright: 2015, Vlad "SATtva" Miller, http://vladmiller.info
    license: GNU GPL, see COPYING for details.
"""

import unittest, socket, io
import gpgremote_client as client
import gpgremote_server as server


socket.setdefaulttimeout(1)


class TestPackage(unittest.TestCase):
    """Data interchange format tests."""

    def test_fields(self):
        """Data fields only."""
        identifier = 'test_id'
        fields = ['foo']
        length, package = client.pack(identifier, *fields)
        unpacked_id, unpacked_fields, unpacked_files = server.unpack(
                                                                package)
        self.assertEqual(length, len(package.getbuffer()))
        self.assertEqual(unpacked_id, identifier)
        self.assertEqual(unpacked_fields, fields)
        self.assertEqual(unpacked_files, {})

    def test_files(self):
        """Data fields and files."""
        identifier = 'test_id'
        fields = ['foo', 'bar', 1]
        files = {'file1': b'file1_data', 'file2': b'file2_data'}
        # As file data is trimmed in pack() function, we'll pass a copy of
        # files dict. This is done merely for later equality test, and must
        # not be used in real code.
        length, package = server.pack(identifier, *fields,
                                      files=files.copy())
        unpacked_id, unpacked_fields, unpacked_files = server.unpack(
                                                                package)
        self.assertEqual(length, len(package.getbuffer()))
        self.assertEqual(unpacked_id, identifier)
        self.assertEqual(unpacked_fields, fields)
        self.assertEqual(unpacked_files, files)


class TestTransmission(unittest.TestCase):
    """Data tranfer tests."""

    def setUp(self):
        self.sender, self.receiver = socket.socketpair()

    def test_short(self):
        """Payload shorter than header."""
        data = b'foobar'
        length = len(data)
        package = io.BytesIO(data)
        client.send(length, package, self.sender)
        received = server.receive(self.receiver)
        self.assertEqual(received.read(), data)

    def test_long(self):
        """Payload longer than header and socket buffer."""
        data = b'a' * 1024 * 128  # BUG: Why does it hangs if > 1024*214?
        length = len(data)
        package = io.BytesIO(data)
        server.send(length, package, self.sender)
        received = client.receive(self.receiver)
        self.assertEqual(received.read(), data)

    def test_limited(self):
        """Stream exceeding length limit."""
        data = b'a' * 1024
        length = len(data)
        package = io.BytesIO(data)
        client.send(length, package, self.sender)
        self.assertRaises(server.StreamLenError, server.receive,
                          self.receiver, len_limit=512)

    def test_enforcement(self):
        """Length enforcement: don't read more than specified in
        the header."""
        data = b'a' * 2045 + b'321' + b'0' * 1024  # 3072 bytes total.
        length = len(data)
        package = io.BytesIO(data)
        client.send(length, package, self.sender, _override_length=2048)
        received = client.receive(self.receiver).read()
        self.assertEqual(received, data[:2048])
        self.assertIs(received.endswith(b'321'), True)

    def test_timeout(self):
        """Timeout connection if stream is shorter than specified in
        the header."""
        data = b'a' * 512
        length = len(data)
        package = io.BytesIO(data)
        client.send(length, package, self.sender, _override_length=1024)
        self.assertRaises(socket.timeout, client.receive, self.receiver)

    def test_unicode(self):
        """Pack and transfer data fields containing multibyte characters."""
        identifier = 'test_id'
        fields = ['мой дядя самых честных правил']
        length, package = client.pack(identifier, *fields)
        server.send(length, package, self.sender)
        received = client.receive(self.receiver)
        unpacked_id, unpacked_fields, unpacked_files = client.unpack(
                                                                received)
        self.assertEqual(unpacked_id, identifier)
        self.assertEqual(unpacked_fields, fields)
        self.assertEqual(unpacked_files, {})

    def tearDown(self):
        self.sender.close()
        self.receiver.close()


if __name__ == '__main__':
    unittest.main()
