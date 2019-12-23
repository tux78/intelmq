# -*- coding: utf-8 -*-
'''
    IntelMQ Exception Class
'''
import traceback

from typing import Any

__all__ = ['InvalidArgument', 'ConfigurationError', 'IntelMQException',
           'IntelMQHarmonizationException', 'InvalidKey', 'InvalidValue',
           'KeyExists', 'KeyNotExists', 'PipelineError',
           'MissingDependencyError',
           ]


class IntelMQException(Exception):

    def __init__(self, message):
        super().__init__(message)


'''
    IntelMQ Exception SubClasses
'''


class InvalidArgument(IntelMQException):

    def __init__(self, argument: Any, got: Any = None, expected=None,
                 docs: str = None):
        message = "Argument {} is invalid.".format(repr(argument))
        if expected is list:
            message += " Should be one of: {}.".format(list)
        elif expected:  # not None
            message += " Should be of type: {}.".format(expected)
        if got:
            message += " Got {}.".format(repr(got))
        if docs:
            message += " For more information see {}".format(docs)
        super().__init__(message)


class PipelineError(IntelMQException):

    def __init__(self, argument):
        if type(argument) is type and issubclass(argument, Exception):
            message = "pipeline failed - %s" % traceback.format_exc(argument)
        else:
            message = "pipeline failed - %s" % repr(argument)
        super().__init__(message)


class ConfigurationError(IntelMQException):

    def __init__(self, config: str, argument: str):
        message = "%s configuration failed - %s" % (config, argument)
        super().__init__(message)


class PipelineFactoryError(IntelMQException):
    pass


'''
    IntelMQ Harmonization Exception Class
'''


class IntelMQHarmonizationException(IntelMQException):

    def __init__(self, message):
        super().__init__(message)


'''
    IntelMQ Harmonization Exception sub classes
'''


class InvalidValue(IntelMQHarmonizationException):

    def __init__(self, key: str, value: str, reason: Any = None):
        message = ("invalid value {value!r} ({type}) for key {key!r}{reason}"
                   "".format(value=value, type=type(value), key=key,
                             reason=': ' + reason if reason else ''))
        super().__init__(message)


class InvalidKey(IntelMQHarmonizationException):

    def __init__(self, key: str):
        message = "invalid key %s" % repr(key)
        super().__init__(message)


class KeyExists(IntelMQHarmonizationException):

    def __init__(self, key: str):
        message = "key %s already exists" % repr(key)
        super().__init__(message)


class KeyNotExists(IntelMQHarmonizationException):

    def __init__(self, key: str):
        message = "key %s not exists" % repr(key)
        super().__init__(message)


class MissingDependencyError(IntelMQException):
    """
    A missing dependency was detected. Log instructions on installation.
    """
    def __init__(self, dependency: str, version: str = None):
        appendix = ""
        if version:
            appendix = (" Please note that this bot requires "
                        "{dependency} {version}!".format(dependency=dependency,
                                                         version=version))
        message = ("Could not load dependency {dependency!r}, please install it "
                   "with apt/yum/dnf/zypper (possibly named "
                   "python3-{dependency}) or pip3.{appendix}"
                   "".format(dependency=dependency,
                             appendix=appendix))
        super().__init__(message)
