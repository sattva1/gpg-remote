# -*- coding: utf-8 -*-

""" GPG Remote server module testing

    copyright: 2015, Vlad "SATtva" Miller, http://vladmiller.info
    license: GNU GPL, see COPYING for details.
"""

import unittest, io
import gpgremote_server as server


class TestParseWhitelist(unittest.TestCase):
    """Whitelist file parsing tests."""

    @staticmethod
    def parse(lines):
        """Call shortening wrapper."""
        return server.parse_whitelist(lines)

    def test_parse(self):
        """Parse whitelist."""
        whitelist = io.StringIO(initial_value="""
# Some comments.
#

foo
-o
--opt
-p name
--param name
-s name --set
-v val1 val2
-w [wildcard]
-f [#NO_FILES]

""")
        parsed = self.parse(whitelist.readlines())
        self.assertEqual(parsed, {'-o': (False, []),
                                  '--opt': (False, []),
                                  '-p': (False, ['name']),
                                  '--param': (False, ['name']),
                                  '-s': (False, ['name']),
                                  '--set': (False, ['name']),
                                  '-v': (False, ['val1', 'val2']),
                                  '-w': (False, [...]),
                                  '-f': (True, [])})

class TestFilterOptions(unittest.TestCase):
    """Options filter tests."""

    whitelist = {'-s': (False, []),
                 '--option': (False, []),
                 '-p': (False, [...]),
                 '--param': (False, ['value'])}

    @staticmethod
    def filter_opts(*args, **kwargs):
        """Call shortening wrapper."""
        return server.filter_options(*args, **kwargs)

    def test_whitelisted_opts(self):
        """Whitelisted options."""
        args = [('-s', None), ('-p', None)]
        filtered = self.filter_opts(args, self.whitelist)
        self.assertEqual(filtered, args)

    def test_whitelisted_opts_params(self):
        """Whitelisted options with parameters."""
        args = [('-s', 'foo'), ('-p', 'bar')]
        filtered = self.filter_opts(args, self.whitelist)
        # Although -s option is not parameterized according to the
        # whitelist, the filter itself should not deal with such a case.
        self.assertEqual(filtered, args)

    def test_args(self):
        """Arguments only."""
        args = [(None, '-p'), (None, 'foo')]
        filtered = self.filter_opts(args, self.whitelist)
        self.assertEqual(filtered, args)

    def test_whitelisted_opts_args(self):
        """Whitelisted options and trailing arguments."""
        args = [('-s', None), ('-p', None), (None, 'foo')]
        filtered = self.filter_opts(args, self.whitelist)
        self.assertEqual(filtered, args)

    def test_filter_opts(self):
        """Filter out options."""
        args = [('--foo', None), ('-s', None), ('--bar', None)]
        filtered = self.filter_opts(args, self.whitelist)
        self.assertEqual(filtered, [('-s', None)])

    def test_filter_opts_params(self):
        """Filter out options with parameters."""
        args = [('--foo', 'bar'), ('-s', None)]
        filtered = self.filter_opts(args, self.whitelist)
        self.assertEqual(filtered, [('-s', None)])

    def test_filter_opts_args(self):
        """Filter out options, leave arguments intact."""
        args = [('--foo', 'bar'), (None, 'arg')]
        filtered = self.filter_opts(args, self.whitelist)
        self.assertEqual(filtered, [(None, 'arg')])

    def test_move_trailing1(self):
        """Don't move last option parameter to trailing arguments if option
        is parameterized."""
        args = [('-p', 'bar')]
        filtered = self.filter_opts(args, self.whitelist)
        self.assertEqual(filtered, args)

    def test_move_trailing2(self):
        """Don't move last option parameter to trailing arguments if
        parameter is absent."""
        args = [('-s', None)]
        filtered = self.filter_opts(args, self.whitelist)
        self.assertEqual(filtered, args)

    def test_move_trailing3(self):
        """Move last option parameter to trailing arguments if option is
        not parameterized."""
        args = [('-s', 'foo')]
        filtered = self.filter_opts(args, self.whitelist)
        self.assertEqual(filtered, [('-s', None), (None, 'foo')])

    def test_move_trailing4(self):
        """Move last option parameter to trailing arguments if option is
        not parameterized. Make sure its placed in front of other
        arguments."""
        args = [('-s', 'foo'), (None, 'arg')]
        filtered = self.filter_opts(args, self.whitelist)
        self.assertEqual(filtered, [('-s', None), (None, 'foo'),
                                    (None, 'arg')])

    def test_strict1(self):
        """Don't raise exception in strict mode if all options are
        whitelisted."""
        args = [('--option', None), ('-p', None)]
        filtered = self.filter_opts(args, self.whitelist, strict=True)
        self.assertEqual(filtered, args)

    def test_strict2(self):
        """Raise exception in strict mode if some options are restricted."""
        args = [('--foo', None), ('-s', None)]
        self.assertRaises(server.RestrictedError,
                          self.filter_opts, args, self.whitelist,
                          strict=True)

    def test_ambiguous1(self):
        """Don't raise exception if long option is unambiguous."""
        whitelist = {'--option': (False, []), '--option-foo': (False, [])}
        args = [('--option', None)]
        filtered = self.filter_opts(args, whitelist)
        self.assertEqual(filtered, args)

    def test_ambiguous2(self):
        """Raise exception if long option is ambiguous."""
        whitelist = {'--option': (False, []), '--option-foo': (False, [])}
        args = [('--opt', None)]
        self.assertRaises(server.AmbiguousError,
                          self.filter_opts, args, whitelist)

    def test_malformed(self):
        """Wrong arguments format raises exception."""
        args = [(None, 'foo'), ('-o', None)]
        self.assertRaises(server.MalformedArgsError,
                          self.filter_opts, args, self.whitelist)


class TestFilterParameters(unittest.TestCase):
    """Parameters filter tests."""

    whitelist = {'-s': (False, []),
                 '--option': (False, []),
                 '-p': (False, [...]),
                 '--param': (False, ['value1', 'value2'])}

    @staticmethod
    def filter_params(*args, **kwargs):
        """Call shortening wrapper."""
        return server.filter_parameters(*args, **kwargs)

    def test_unparameterized(self):
        """Unparameterized options only."""
        args = [('--option', None), ('-s', None)]
        filtered = self.filter_params(args, self.whitelist)
        self.assertEqual(filtered, args)

    def test_param_wildcard(self):
        """Wildcard parameter whitelist."""
        args = [('-p', 'foo')]
        filtered = self.filter_params(args, self.whitelist)
        self.assertEqual(filtered, args)

    def test_param_whitelist(self):
        """Whitelisted parameter value."""
        args = [('--param', 'value2')]
        filtered = self.filter_params(args, self.whitelist)
        self.assertEqual(filtered, args)

    def test_param_restricted(self):
        """Restricted parameter value."""
        args = [('--param', 'foo')]
        filtered = self.filter_params(args, self.whitelist)
        self.assertEqual(filtered, [])

    def test_param_empty1(self):
        """Empty parameter value for parameterized option with wildcard
        whitelist."""
        args = [('-p', None)]
        filtered = self.filter_params(args, self.whitelist)
        self.assertEqual(filtered, args)

    def test_param_empty2(self):
        """Empty parameter value for parameterized option with non-wildcard
        whitelist."""
        args = [('--param', None)]
        filtered = self.filter_params(args, self.whitelist)
        self.assertEqual(filtered, [])

    def test_param_strict(self):
        """Raise exception in strict mode for restricted parameter value."""
        args = [('--param', 'foo')]
        self.assertRaises(server.RestrictedError, self.filter_params,
                          args, self.whitelist, strict=True)

    def test_param_malformed(self):
        """Raise exception if parameter is provided for unparameterized
        option."""
        args = [('--option', 'foo')]
        self.assertRaises(server.MalformedArgsError, self.filter_params,
                          args, self.whitelist)


class TestGetNoFilesFlag(unittest.TestCase):
    """Get no_files function tests."""

    whitelist = {'-s': (False, []),
                 '--option': (False, []),
                 '-p': (True, [])}

    @staticmethod
    def get_flag(*args, **kwargs):
        """Call shortening wrapper."""
        return server.get_no_files_flag(*args, **kwargs)

    def test_no_flag(self):
        """No flag in passed options."""
        args = [('--option', None), ('-s', None)]
        flag = self.get_flag(args, self.whitelist)
        self.assertIs(flag, False)

    def test_has_flag(self):
        """Flag is present in passed options."""
        args = [('--option', None), ('-p', None)]
        flag = self.get_flag(args, self.whitelist)
        self.assertIs(flag, True)


class TestOption(unittest.TestCase):
    """Get option value if any."""

    def test_no_output(self):
        """No output options provided in arguments list."""
        args = [('--foo', 'param'), ('--bar', None)]
        output = server.get_option(args, server.OUTPUT_OPTS)
        self.assertEqual(output, (None, None))

    def test_output(self):
        """Output option provided in arguments list."""
        args = [('-o', 'some/path'), ('--bar', None)]
        output = server.get_option(args, server.OUTPUT_OPTS)
        self.assertEqual(output, ('some/path', 0))

    def test_output_multiple1(self):
        """Multiple output options provided in arguments list."""
        args = [('-o', 'some/path'), ('--output', 'another_path')]
        output = server.get_option(args, server.OUTPUT_OPTS)
        self.assertEqual(output, ('another_path', 1))

    def test_output_multiple2(self):
        """Multiple output options provided in arguments list, get all."""
        args = [('-o', 'some/path'), ('--foo', None),
                ('--output', 'another_path')]
        output = server.get_option(args, server.OUTPUT_OPTS, get_all=True)
        self.assertEqual(output, [('some/path', 0), ('another_path', 2)])


if __name__ == '__main__':
    unittest.main()
