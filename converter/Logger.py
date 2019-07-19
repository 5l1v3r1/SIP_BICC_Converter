#!/usr/bin/env python
# coding: utf-8

import sys 
import logging
import os
import inspect
import datetime
from options import options

__author__ = 'Divyanshu Chauhan <divyanshu0045@gmail.com>'
__date__ = '24 Dec 2018'

class logger():

    log = None

    def __init__(self, level = logging.INFO, logfile = options.logfile, console_log = options.console_log):
    	self.logger = logging.getLogger(__file__)
        self.logger.setLevel(level)
        
        formatter = logging.Formatter(('%(asctime)s|%(levelname)s|%(thread)d|%(message)s'))
        if (logfile):
            fh = logging.FileHandler('%s.%s' % (logfile, datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")))
            fh.setFormatter(formatter)
            fh.setLevel(level)
            self.logger.addHandler(fh)

        if (console_log):
            sh = logging.StreamHandler()
            sh.setFormatter(formatter)
            sh.setLevel(logging.INFO)
            self.logger.addHandler(sh)

    @staticmethod
    def get_logger():
        if (logger.log == None):
            logger.log = logger(console_log = True)
        return logger.log

    def append_callerinfo_to_msg(self, caller_info, msg):
        (filename, line_no, func_name, lines, index) = inspect.getframeinfo(caller_info)
        msg = '|'.join([str(os.path.basename(filename)), str(func_name), str(line_no), msg])
        return msg

    def debug(self, msg):
        if (options.detailed_log):
            caller_info = inspect.currentframe().f_back
            msg = self.append_callerinfo_to_msg(caller_info, msg)
        self.logger.debug(msg)

    def info(self, msg):
        if (options.detailed_log):
            caller_info = inspect.currentframe().f_back
            msg = self.append_callerinfo_to_msg(caller_info, msg)
        self.logger.info(msg)
        pass

    def warning(self, msg):
        if (options.detailed_log):
            caller_info = inspect.currentframe().f_back
            msg = self.append_callerinfo_to_msg(caller_info, msg)
        self.logger.warning(msg)

    def error(self, msg):
        if (options.detailed_log):
            caller_info = inspect.currentframe().f_back
            msg = self.append_callerinfo_to_msg(caller_info, msg)
        self.logger.error(msg)

