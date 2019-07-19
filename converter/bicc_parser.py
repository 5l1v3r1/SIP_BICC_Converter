#!/usr/bin/python
# -*- coding: UTF-8 -*-
# -*- Mode: Python -*-

__author__ = 'Divyanshu Chauhan <divyanshu0045@gmail.com>'
__date__ = '04 Jun 2019'

import sys
from struct import *
from Logger import logger

class bicc_parser():
    log = logger.get_logger()
    def __init__(self, msg=None, cic=0):
        self.msg = msg

        self.cic = 0
        self.msg_type = 0
        self.called_party_num = 0
        self.calling_party = None
        self.iam_sdp = None
        self.iam_sdp_ip = None
        self.iam_sdp_port = None
        self.apm_sdp = None
        self.apm_sdp_ip = None
        self.apm_sdp_port = None

    def parse_sdp(self, sdp, ipbcp_type):
        sdplines = sdp.splitlines()
        for line in sdplines:
            if (ipbcp_type == "Accepted"):
                if "c=IN" in line:
                    self.apm_sdp_ip = line.split()[-1]
                if "m=audio" in line:
                    self.apm_sdp_port = line.split()[1]
            if (ipbcp_type == "Request"):
                if "c=IN" in line:
                    self.iam_sdp_ip = line.split()[-1]
                if "m=audio" in line:
                    self.iam_sdp_port = line.split()[1]

    def msisdn_decode(self,msisdn):
        j = 0
        decoded = [None] * 100
        for i in range(len(msisdn)):
            decoded[j] = str(ord(msisdn[i]) & 0x0f )
            decoded[j+1] = 0 if ((ord(msisdn[i]) & 0xf0)==240) else str((ord(msisdn[i]) & 0xf0)>>4)
            j+=2

        decoded = [str(x) for x in decoded if x != None]
        return ''.join(decoded)

    def parse_iam(self, data):
        if (self.msg == None):
            self.msg = str(data)
        len_bparty = unpack('B',self.msg[12])[0]
        calledAddr = self.msg[15:15+len_bparty-2]
        self.called_party_num = self.msisdn_decode(calledAddr)
        len_aparty = unpack('B',self.msg[12+len_bparty+2])[0]
        callingAddr = self.msg[12+len_bparty+5:len_aparty-2+12+len_bparty+5] 
        self.calling_party = self.msisdn_decode(callingAddr)
        self.iam_sdp = self.msg[89+len_bparty+len_aparty:]
        self.parse_sdp(self.iam_sdp, "Request")


    def parse_apm(self, data):
        if (self.msg == None):
            self.msg = str(data)
        self.apm_sdp = self.msg[23:]
        self.parse_sdp(self.apm_sdp, "Accepted")

    def parse_anm(self,data):
        if (self.msg == None):
            self.msg = str(data)
        pass

    def parse_acm(self,data):
        if (self.msg == None):
            self.msg = str(data)
        pass

    def parse_rel(self,data):
        if (self.msg == None):
            self.msg = str(data)
        pass

    def parse_rlc(self,data):
        if (self.msg == None):
            self.msg = str(data)
        pass
