# -*- coding: utf-8 -*-

""" GPG Remote client module testing

    copyright: 2015, Vlad "SATtva" Miller, http://vladmiller.info
    license: GNU GPL, see COPYING for details.
"""

import unittest, tempfile
import gpgremote_client as client


class TestUpdateConfig(unittest.TestCase):
    """Config parser tests."""

    def test_parse(self):
        """Parse proper config file."""
        with tempfile.NamedTemporaryFile(prefix='gpgremote_test_',
                                         mode='wt', delete=False) as file:
            file.write("""
# Comment.

foo = bar
value = 1
flag
""")
        parsed = {}
        expected = {'foo': 'bar', 'value': 1, 'flag': True}
        client.update_config(file.name, parsed)
        self.assertEqual(parsed, expected)

    def test_silent(self):
        """Supress errors in silent mode."""
        parsed = {'foo': 'bar'}
        expected = {'foo': 'bar'}
        client.update_config('/foobar', parsed)
        self.assertEqual(parsed, expected)

    def test_nonsilent(self):
        """Raise error in non-silent mode."""
        self.assertRaises(ValueError, client.update_config,
                          '/foobar', {}, silent=False)


class TestParseOptions(unittest.TestCase):
    """Command line arguments parsing tests."""

    @staticmethod
    def parse(argv):
        """Call shortening wrapper."""
        return client.parse_options(argv)

    def test_empty(self):
        """No arguments."""
        argv = []
        parsed = self.parse(argv)
        self.assertEqual(parsed, [])

    def test_opts1(self):
        """Options without parameters, case 1."""
        argv = ['-o']
        parsed = self.parse(argv)
        self.assertEqual(parsed, [('-o', None)])

    def test_opts2(self):
        """Options without parameters, case 2."""
        argv = ['-o', '--option']
        parsed = self.parse(argv)
        self.assertEqual(parsed, [('-o', None), ('--option', None)])

    def test_opts_params1(self):
        """Options with parameters, case 1."""
        argv = ['-o', 'foo']
        parsed = self.parse(argv)
        self.assertEqual(parsed, [('-o', 'foo')])

    def test_opts_params2(self):
        """Options with parameters, case 2."""
        argv = ['-o', 'foo', '--output', 'bar']
        parsed = self.parse(argv)
        self.assertEqual(parsed, [('-o', 'foo'), ('--output', 'bar')])

    def test_args1(self):
        """Trailing arguments only, case 1."""
        argv = ['foo']
        parsed = self.parse(argv)
        self.assertEqual(parsed, [(None, 'foo')])

    def test_args2(self):
        """Trailing arguments only, case 2."""
        argv = ['foo', 'bar']
        parsed = self.parse(argv)
        self.assertEqual(parsed, [(None, 'foo'), (None, 'bar')])

    def test_opts_args(self):
        """Options and trailing arguments."""
        argv = ['-o', 'foo', 'bar']
        parsed = self.parse(argv)
        self.assertEqual(parsed, [('-o', 'foo'), (None, 'bar')])

    def test_args_explicit(self):
        """Explicitly defined trailing arguments."""
        argv = ['--', '-o', 'foo']
        parsed = self.parse(argv)
        self.assertEqual(parsed, [(None, '-o'), (None, 'foo')])

    def test_opt_args_explicit(self):
        """Option and explicitly defined trailing arguments."""
        argv = ['-o', '--', 'foo', 'bar']
        parsed = self.parse(argv)
        self.assertEqual(parsed, [('-o', None),
                                  (None, 'foo'), (None, 'bar')])

    def test_opts_expand(self):
        """Expand multiple shortened options."""
        argv = ['-op']
        parsed = self.parse(argv)
        self.assertEqual(parsed, [('-o', None), ('-p', None)])

    def test_opts_param_expand(self):
        """Expand multiple shortened options with parameter."""
        argv = ['-op', 'foo']
        parsed = self.parse(argv)
        self.assertEqual(parsed, [('-o', None), ('-p', 'foo')])

    def test_posix1(self):
        """POSIX compliance, case 1."""
        argv = ['foo', '-o']
        parsed = self.parse(argv)
        self.assertEqual(parsed, [('-o', None)])

    def test_posix2(self):
        """POSIX compliance, case 2."""
        argv = ['--option', 'foo', 'bar', '-o']
        parsed = self.parse(argv)
        self.assertEqual(parsed, [('--option', 'foo'), ('-o', None)])

    def test_stdout(self):
        """STDOUT placeholder."""
        argv = ['-o', '-', '-']
        parsed = self.parse(argv)
        self.assertEqual(parsed, [('-o', '-'), (None, '-')])

    def test_complex(self):
        """Complex case."""
        argv = ['non-posix', '--option', 'foo', 'non-posix',
                '-ovp', 'two words', '-a', 'param', '--',
                '--opt', 'arg1', 'arg2']
        parsed = self.parse(argv)
        self.assertEqual(parsed, [('--option', 'foo'),
                                  ('-o', None), ('-v', None),
                                  ('-p', 'two words'), ('-a', 'param'),
                                  (None, '--opt'), (None, 'arg1'),
                                  (None, 'arg2')])


class TestGetFilenames(unittest.TestCase):
    """File names of existing files in command line arguments tests."""

    def test_missing(self):
        """No existing files in args list."""
        args = [(None, '/foo')]  # Hopefully there is no such file.
        files = client.get_filenames(args)
        self.assertEqual(files, [])

    def test_ignore_output(self):
        """Ignore existing files given in --output option."""
        file = tempfile.NamedTemporaryFile(prefix='gpgremote_test_')
        args = [('--output', file.name)]
        files = client.get_filenames(args)
        self.assertEqual(files, [])

    def test_existing(self):
        """Output existing filename."""
        file = tempfile.NamedTemporaryFile(prefix='gpgremote_test_')
        args = [('--opt1', file.name), ('--opt2', '/foo')]
        files = client.get_filenames(args)
        self.assertEqual(files, [file.name])


if __name__ == '__main__':
    unittest.main()
