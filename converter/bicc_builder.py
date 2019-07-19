#!/usr/bin/python
# -*- coding: UTF-8 -*-
# -*- Mode: Python -*-

__author__ = 'Divyanshu Chauhan <divyanshu0045@gmail.com>'
__date__ = '04 Jun 2019'

from Logger import logger

class bicc_builder():
    log = logger.get_logger()
    def __init__(self,sctp_socket,cic=0):

        self.iam_buf = None
        self.apm_buf = None
        self.acm_buf = None
        self.anm_buf = None
        self.rel_buf = None
        self.rlc_buf = None
        self.apm_dtmf_start = None
        self.apm_dtmf_stop = None

        with open('iam_buf','rb') as f:
            self.iam_buf = (f.read().strip())
        with open('apm_buf','rb') as f:
            self.apm_buf = (f.read().strip())
        with open('acm_buf','rb') as f:
            self.acm_buf = (f.read().strip())
        with open('anm_buf','rb') as f:
            self.anm_buf = (f.read().strip())
        with open('rel_buf','rb') as f:
            self.rel_buf = (f.read().strip())
        with open('rlc_buf','rb') as f:
            self.rlc_buf = (f.read().strip())
        with open('apm_dtmf_start','rb') as f:
            self.apm_dtmf_start = (f.read().strip())
        with open('apm_dtmf_stop','rb') as f:
            self.apm_dtmf_stop = (f.read().strip())

        self.cic = cic
        self.sctp_sock = sctp_socket
       
    def encode_msisdn(self,num):
        j = 0
        l=len(num)
        a=num
        if l%2!=0:
            a=a+'f'
        num = ''.join([x[::-1] for x in [a[i:i+2] for i in range(0, len(a), 2)]])
        return bytearray(num),len(num)

    def make_sdp(self,sdp,ipbcp_type):
        new_sdp = list()
        sdp_lines=sdp.splitlines()
        sdp_port = 0
        sdp_ip = str()
        for line in sdp_lines:
            if 'c=IN' in line:
                sdp_ip = line.split()[-1]
            if 'm=audio' in line:
                sdp_port = line.split()[1]
        
        new_sdp.append('v=0')
        new_sdp.append('o=Test 0 0 IN IP4 %s' %(sdp_ip))
        new_sdp.append('s=-')
        new_sdp.append('c=IN IP4 %s' %(sdp_ip))
        new_sdp.append('t=0 0')
        new_sdp.append('a=ipbcp:1 %s' %(ipbcp_type))
        new_sdp.append('m=audio %s RTP/AVP 127' %(sdp_port))
        #new_sdp.append('m=audio %s RTP/AVP 8' %(sdp_port))
        new_sdp.append('a=ptime:5')
        new_sdp.append('a=rtpmap:127 VND.3GPP.IUFP/16000')
        #new_sdp.append('a=rtpmap:8 PCMA/8000')
        new_sdp = '\r\n'.join(new_sdp)
        new_sdp = new_sdp + '\r\n'
        len_sdp = len(new_sdp)
        new_sdp = ''.join([str(format(ord(x),'x')).zfill(2) for x in new_sdp])
        return new_sdp,len_sdp

    def cic_to_network_order(self, cic_str):
        return "".join(reversed([cic_str[i:i+2] for i in range(0, len(cic_str), 2)]))

    def make_apm_dtmf_start(self, digit=None):
        old_apm_cic = self.apm_dtmf_start[0:8]
        new_apm = self.apm_dtmf_start.replace(old_apm_cic,self.cic_to_network_order(str(format(self.cic,'x')).zfill(8)), 1)
        if (digit == '*'):
            new_apm = new_apm.replace("05",str(format(int('10'),'x')).zfill(2))
        elif (digit == '#'):
            new_apm = new_apm.replace("05",str(format(int('11'),'x')).zfill(2))
        else:
            new_apm = new_apm.replace("05",str(format(int(digit),'x')).zfill(2))
        bicc_builder.log.info ("SENDING APM DTMF START on CIC:%s with DIGIT:%s" % (self.cic, digit))
        self.sctp_sock.send(bytes(bytearray.fromhex(new_apm.strip())))    
        return new_apm

    def make_apm_dtmf_stop(self):
        old_apm_cic = self.apm_dtmf_stop[0:8]
        new_apm = self.apm_dtmf_stop.replace(old_apm_cic,self.cic_to_network_order(str(format(self.cic,'x')).zfill(8)), 1)
        bicc_builder.log.info ("SENDING APM DTMF STOP on CIC:%s" % (self.cic))
        self.sctp_sock.send(bytes(bytearray.fromhex(new_apm.strip())))    
        return new_apm

    def make_iam(self,called,calling,new_sdp,src_ip):
        new_sdp,new_sdp_len=self.make_sdp(new_sdp, 'Request')
        encoded_called,len_called=self.encode_msisdn(called)
        encoded_calling,len_calling=self.encode_msisdn(calling)
        called_party_len = self.iam_buf[24:26] #5
        called_party_num = self.iam_buf[30:36] #29843F
        calling_party_len = self.iam_buf[38:40] #8
        calling_party_num = self.iam_buf[44:56] #01977141347F
        iwfa_ip = self.iam_buf[110:118] #10.231.0.81
        sdp = self.iam_buf[204:]
        old_iam_cic = self.iam_buf[0:8]
        old_ptr_opt = self.iam_buf[22:24]
        new_iam = self.iam_buf.replace(old_iam_cic,self.cic_to_network_order(str(format(self.cic,'x')).zfill(8)), 1)
        new_iam = new_iam.replace(old_ptr_opt, str((int(len_called)/2) + 4).zfill(2), 1)
        new_iam = new_iam[:24] + str((int(len_called)/2) +2).zfill(2) + new_iam[26:]
        new_iam = new_iam[:38] + str((int(len_calling)/2) +2).zfill(2) + new_iam[40:]
        new_iam = new_iam[:110] + format(int(src_ip.split('.')[0]),'x').zfill(2) + new_iam[112:] 
        new_iam = new_iam[:112] + format(int(src_ip.split('.')[1]),'x').zfill(2) + new_iam[114:] 
        new_iam = new_iam[:114] + format(int(src_ip.split('.')[2]),'x').zfill(2) + new_iam[116:] 
        new_iam = new_iam[:116] + format(int(src_ip.split('.')[3]),'x').zfill(2) + new_iam[118:] 
        new_iam = new_iam.replace("e6",str(format(new_sdp_len+69,'x')).zfill(2), 1)
        new_iam = new_iam.replace(called_party_num,encoded_called)
        new_iam = new_iam.replace(calling_party_num, encoded_calling)
        new_iam = new_iam[:-326]
        new_iam = new_iam + new_sdp
        #new_iam = new_iam.replace(sdp, new_sdp)
        #new_iam = new_iam[:44] + encoded_calling + new_iam[56:]
        #new_iam = new_iam[:30] + encoded_called + new_iam[36:]
        #new_iam = new_iam[:191+len_called+len_calling+4] + new_sdp
        new_iam = new_iam.decode('utf-8')
        bicc_builder.log.info ("SENDING IAM on CIC:%s" % (self.cic))
        self.sctp_sock.send(bytes(bytearray.fromhex(new_iam.strip())))    
        return new_iam

    def make_apm(self,new_sdp):
        sdp=self.apm_buf[46:]
        old_apm_cic = self.apm_buf[0:8]
        new_apm = self.apm_buf.replace(old_apm_cic,self.cic_to_network_order(str(format(self.cic,'x')).zfill(8)), 1)
        new_sdp,new_sdp_len=self.make_sdp(new_sdp, 'Accepted')
        new_apm = new_apm[:46] + new_sdp 
        new_apm = new_apm.replace("b1",str(format(new_sdp_len+15,'x')).zfill(2))
        bicc_builder.log.info ("SENDING APM on CIC:%s" % (self.cic))
        self.sctp_sock.send(bytes(bytearray.fromhex(new_apm.strip())))    
        return new_apm

    def make_acm(self):
        old_acm_cic = self.acm_buf[0:8]
        new_acm=self.acm_buf.replace(old_acm_cic,self.cic_to_network_order(str(format(self.cic,'x')).zfill(8)), 1)
        bicc_builder.log.info ("SENDING ACM on CIC:%s" % (self.cic))
        self.sctp_sock.send(bytes(bytearray.fromhex(new_acm.strip())))    
        return new_acm

    def make_anm(self):
        old_anm_cic = self.anm_buf[0:8]
        new_anm=self.anm_buf.replace(old_anm_cic,self.cic_to_network_order(str(format(self.cic,'x')).zfill(8)), 1)
        bicc_builder.log.info ("SENDING ANM on CIC:%s" % (self.cic))
        self.sctp_sock.send(bytes(bytearray.fromhex(new_anm.strip())))    
        return new_anm

    def make_rel(self):
        old_rel_cic = self.rel_buf[0:8]
        new_rel=self.rel_buf.replace(old_rel_cic,self.cic_to_network_order(str(format(self.cic,'x')).zfill(8)), 1)
        bicc_builder.log.info ("SENDING REL on CIC:%s" % (self.cic))
        self.sctp_sock.send(bytes(bytearray.fromhex(new_rel.strip())))    
        return new_rel

    def make_rlc(self):
        old_rlc_cic = self.rlc_buf[0:8]
        new_rlc=self.rlc_buf.replace(old_rlc_cic,self.cic_to_network_order(str(format(self.cic,'x')).zfill(8)), 1)
        bicc_builder.log.info ("SENDING RLC on CIC:%s" % (self.cic))
        self.sctp_sock.send(bytes(bytearray.fromhex(new_rlc.strip())))    
        return new_rlc
        



        
