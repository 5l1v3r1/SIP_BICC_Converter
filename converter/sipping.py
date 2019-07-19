#!/usr/bin/python
# -*- coding: UTF-8 -*-
# -*- Mode: Python -*-

__author__ = 'Divyanshu Chauhan <divyanshu0045@gmail.com>'
__date__ = '04 Jun 2019'

import socket
import time
import sys
import optparse
import select
import cStringIO
import re
import struct
import sctp
import time
import os
import traceback
import random
import string
from threading import Thread
from string import Template

from options import options
from bicc_parser import bicc_parser
from bicc_builder import bicc_builder
from Logger import logger
from ThreadPool import ThreadPool

def_request = """OPTIONS sip:%(dest_ip)s:%(dest_port)s SIP/2.0
Via: SIP/2.0/UDP %(source_ip)s:%(source_port)s
Max-Forwards: 70
From: "fake" <sip:fake@%(source_ip)s>
To: <sip:%(dest_ip)s:%(dest_port)s>
Contact: <sip:fake@%(source_ip)s:%(source_port)s>
Call-ID: fake-id@%(source_ip)s
User-Agent: SIPPing
Date: Wed, 24 Apr 2013 20:35:23 GMT
Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH
Supported: replaces, timer"""


def_out = ""

def console_print (msg):
    print(msg.strip())

class CustomTemplate(Template):
    idpattern = r'[a-z][\.\-_a-z0-9]*'


class SipError(Exception):
    pass


class SipUnpackError(SipError):
    pass


class SipNeedData(SipUnpackError):
    pass


class SipPackError(SipError):
    pass


def sctp_cb(msg, fromaddr):
    global udp_sock, sctp_sock, cs
    try:
        c = cs.bycic(msg)
        if c == None:
            return
        c.sctp_dest_ip = fromaddr[0]
        c.sctp_dest_port = fromaddr[1]
        log.info ("Message type:%d received for cic:%d"% (c.bicc_msg_type, c.bicc_cic))
        if (c.bicc_msg_type == 0x01):
            log.info ("IAM Received on CIC:%d" %(c.bicc_cic))
            c.bicc_parser.parse_iam(msg)
            c.bicc_called = c.bicc_parser.called_party_num
            c.bicc_calling = c.bicc_parser.calling_party

            ##HACK TO DIVERT CALL TO ANOTHER SOFTPHONE##
            if ("67890" in c.bicc_called):
                c.udp_dest_ip = "10.0.230.46"
                c.udp_dest_port = 5080

            options.request_template='invite.tmpl'
            options.var=['from_number:%s'%(c.bicc_calling),
            'to_number:%s'%(c.bicc_called),
            'source_ip:%s'%(c.udp_source_ip),
            'dest_ip:%s'%(c.udp_dest_ip),
            'call-id:%s'%(c.sip_callid),
            'cseq:%s'%(c.sip_cseq),
            'source_port:%d'%(c.udp_source_port),
            'dest_port:%d'%(c.udp_dest_port),
            'call_branch:%s'%(c.sip_branch),
            'from_tag:%s'%(c.sip_from_tag),
            'to_tag:%s'%(c.sip_to_tag),
            'contact:%s'%(c.sip_mycontact),
            'sdp_ip:%s'%(c.bicc_parser.iam_sdp_ip),
            'sdp_port:%s'%(c.bicc_parser.iam_sdp_port)]
            tp.push([create_and_send_sip,options,c])
            log.info ("IAM Processed on CIC:%d" %(c.bicc_cic))
        if (c.bicc_msg_type == 0x41):
            log.info ("APM Received on CIC:%d" %(c.bicc_cic))
            c.bicc_parser.parse_apm(msg)
            log.info ("APM Processed on CIC:%d" %(c.bicc_cic))
        if (c.bicc_msg_type == 0x06):
            log.info ("ACM Received on CIC:%d" %(c.bicc_cic))
            c.bicc_parser.parse_acm(msg)
            options.request_template='180-ringing.tmpl'
            options.var=['from_number:%s'%(c.bicc_calling),
            'to_number:%s'%(c.bicc_called),
            'source_ip:%s'%(c.udp_source_ip),
            'dest_ip:%s'%(c.udp_dest_ip),
            'call-id:%s'%(c.sip_callid),
            'cseq:%s'%(c.sip_cseq),
            'source_port:%d'%(c.udp_source_port),
            'dest_port:%d'%(c.udp_dest_port),
            'call_branch:%s'%(c.sip_branch),
            'from_tag:%s'%(c.sip_from_tag),
            'to_tag:%s'%(c.sip_to_tag),
            'contact:%s'%(c.sip_mycontact),
            'sdp_ip:%s'%(c.bicc_parser.iam_sdp_ip),
            'sdp_port:%s'%(c.bicc_parser.iam_sdp_port)]
            tp.push([create_and_send_sip,options,c])
            log.info ("ACM Processed on CIC:%d" %(c.bicc_cic))
        if (c.bicc_msg_type == 0x09):
            log.info ("ANM Received on CIC:%d" %(c.bicc_cic))
            c.bicc_parser.parse_anm(msg)
            options.request_template='200-cseq-invite.tmpl'
            if (c.bicc_parser.apm_sdp_ip == None):
                c.bicc_parser.apm_sdp_ip = str(options.default_sdp_ip)
            if (c.bicc_parser.apm_sdp_port == None):
                c.bicc_parser.apm_sdp_port = str(options.default_sdp_port)
            options.var=['from_number:%s'%(c.bicc_calling),
            'to_number:%s'%(c.bicc_called),
            'source_ip:%s'%(c.udp_source_ip),
            'dest_ip:%s'%(c.udp_dest_ip),
            'call-id:%s'%(c.sip_callid),
            'cseq:%s'%(c.sip_cseq),
            'source_port:%d'%(c.udp_source_port),
            'dest_port:%d'%(c.udp_dest_port),
            'call_branch:%s'%(c.sip_branch),
            'from_tag:%s'%(c.sip_from_tag),
            'to_tag:%s'%(c.sip_to_tag),
            'contact:%s'%(c.sip_mycontact),
            'sdp_ip:%s'%(c.bicc_parser.apm_sdp_ip),
            'sdp_port:%s'%(c.bicc_parser.apm_sdp_port)]
            tp.push([create_and_send_sip,options,c])
            log.info ("ANM Processed on CIC:%d" %(c.bicc_cic))
        if (c.bicc_msg_type == 0x0c):
            log.info ("REL Received on CIC:%d" %(c.bicc_cic))
            c.bicc_parser.parse_rel(msg)
            options.request_template='bye.tmpl'
            options.var=['from_number:%s'%(c.bicc_calling),
            'to_number:%s'%(c.bicc_called),
            'source_ip:%s'%(c.udp_source_ip),
            'dest_ip:%s'%(c.udp_dest_ip),
            'call-id:%s'%(c.sip_callid),
            'cseq:%s'%(c.sip_cseq),
            'source_port:%d'%(c.udp_source_port),
            'dest_port:%d'%(c.udp_dest_port),
            'call_branch:%s'%(c.sip_branch),
            'from_tag:%s'%(c.sip_from_tag),
            'to_tag:%s'%(c.sip_to_tag),
            'contact:%s'%(c.sip_mycontact),
            'sdp_ip:%s'%(c.bicc_parser.iam_sdp_ip),
            'sdp_port:%s'%(c.bicc_parser.iam_sdp_port),
            'remote_contact:%s'%(c.sip_remotecontact)]
            tp.push([create_and_send_sip,options,c])
            tp.push([c.bicc_builder.make_rlc])
            log.info ("REL Processed on CIC:%d" %(c.bicc_cic))
        if (c.bicc_msg_type == 0x10):
            log.info ("RLC Received on CIC:%d" %(c.bicc_cic))
            c.bicc_parser.parse_rlc(msg)
            options.request_template='200-cseq-bye.tmpl'
            options.var=['from_number:%s'%(c.bicc_calling),
            'to_number:%s'%(c.bicc_called),
            'source_ip:%s'%(c.udp_source_ip),
            'dest_ip:%s'%(c.udp_dest_ip),
            'call-id:%s'%(c.sip_callid),
            'cseq:%s'%(c.sip_cseq),
            'source_port:%d'%(c.udp_source_port),
            'dest_port:%d'%(c.udp_dest_port),
            'call_branch:%s'%(c.sip_branch),
            'from_tag:%s'%(c.sip_from_tag),
            'to_tag:%s'%(c.sip_to_tag),
            'contact:%s'%(c.sip_mycontact),
            'sdp_ip:%s'%(c.bicc_parser.iam_sdp_ip),
            'sdp_port:%s'%(c.bicc_parser.iam_sdp_port)]
            tp.push([create_and_send_sip,options,c])
            log.info ("RLC Processed on CIC:%d" %(c.bicc_cic))
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        log.info('|'.join([str(exc_type), str(fname), str(exc_tb.tb_lineno)]))
        log.info (str(e))
    return

class sctp_server:
    def __init__(self, ip, port, cb = None):
        self.sock = sctp.sctpsocket_tcp(socket.AF_INET)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.sock.setblocking(0)
        self.cb = cb
        self.ip = ip
        self.port = port
        self.client = None
        self.data_sent = None
        self.data_rcvd = None
        self.bind()
        self.listen()
        t = Thread(target=self.accept)
        t.daemon = True
        t.start()

    def accept(self):
        while True:
            try:
                client, address = self.sock.accept()
                #client.setblocking(0)
                self.client = client
                log.info ("Incoming SCTP connection %r:%s"%(client,address))
                t = Thread(target=self.recv, args=(client,))
                t.daemon = True
                t.start()
            except Exception as e:
                #log.info ("Accept:"+str(e))
                pass
            finally:
                time.sleep(1)

    def listen(self, backlog=5):
        log.info ("Listening for SCTP connections on socket %r..."%(self.sock))
        self.sock.listen(backlog)

    def send(self, data):
        try:
            bytes = self.client.sctp_send(data,ppid=0x08000000 )
            self.data_sent = data
            return bytes
        except Exception as e:
            log.info ("Cannot send message. " + str(e))

    def bind(self):
        self.sock.bind((self.ip, self.port))

    def set_recv_cb(self, cb):
        self.cb = cb

    def recv(self, sock, size=1024):
        while True:
            try:
                read=[sock]
                inputready, outputready, exceptready = select.select(read, [], [], options.timeout)
                for s in inputready:
                    if s==sock:
                        fromaddr, flags, data, notif = sock.sctp_recv(size)
                        if (self.data_rcvd == data):
                            continue
                        else:
                            self.data_rcvd = data
                            log.info ("Data received from %s on SCTP socket" % (str(fromaddr)))
                            if (self.cb):
                                tp.push([self.cb, data, fromaddr])
            except Exception as e:
                log.info (str(e))

class callsession():
    def __init__(self):
        self.bicc_parser = bicc_parser()
        self.bicc_builder = bicc_builder(sctp_sock)
        self.bicc_apm_sdp = None
        self.bicc_apm_sdp_ip = None
        self.bicc_apm_sdp_port = None
        self.bicc_iam_sdp = None
        self.bicc_iam_sdp_ip = None
        self.bicc_iam_sdp_port = None
        self.bicc_sent = 0
        self.bicc_rcvd = 0
        self.bicc_called = 0
        self.bicc_calling = 0
        self.bicc_cic = 0
        self.bicc_msg_type = 0
       
        self.sip_from_tag = "to_tag"
        self.sip_to_tag = "from_tag"
        self.sip_branch = "call_branch"
        self.sip_to = None
        self.sip_from = None
        self.sip_sent = 0
        self.sip_rcvd = 0
        self.sip_callid = 0
        self.sip_cseq = 0
        self.sip_callid = None
        self.sip_mycontact = None
        self.sip_remotecontact = None

        self.udp_source_ip = options.source_ip #converter sip/udp ip
        self.udp_source_port = options.source_port #converter sip/udp port
        self.udp_dest_port = options.dest_port #sip phone udp port
        self.udp_dest_ip = options.dest_ip #sip phone udp ip
        self.sctp_dest_ip = options.sctp_dest_ip #bicc dialer sctp ip
        self.sctp_dest_port = options.sctp_dest_port #bicc dialer sctp port 
        self.sctp_source_ip = options.sctp_source_ip #converter bicc/sctp ip
        self.sctp_source_port = options.sctp_source_port #converter bicc/sctp port


    @staticmethod
    def createcall(sip=None, bicc=None):
        global activecalllist
        call = callsession()

        if (sip != None):
            resp = sip
            call.sip_to = re.search('sip:(.+)@(.+)', resp.headers['to']).group(1)
            call.sip_from = re.search('sip:(.+)@(.+)', resp.headers['from']).group(1)
            call.sip_cseq = resp.headers['cseq']
            call.sip_callid = resp.headers['call-id']
            call.sip_branch = resp.headers['via'].split('=')[-1]
            call.sip_from_tag = resp.headers['from'].split('=')[-1] if 'tag' in resp.headers['from'] else 'from_tag'
            call.sip_to_tag = resp.headers['to'].split('=')[-1] if 'tag' in resp.headers['to'] else 'to_tag'
            call.sip_mycontact = str(call.sip_to) + '@' + str(options.source_ip) + ':' + str(options.source_port)
            try:
                call.sip_remotecontact = resp.headers['contact'] 
            except:
                if (None == call.sip_remotecontact):
                    call.sip_remotecontact = 'sip:%s@%s:%d' % (call.sip_to, call.udp_dest_ip, call.udp_dest_port)
            for i in range(options.first_cic,options.last_cic):
                cic_used = False
                for c in activecalllist:
                    if i == c.bicc_cic:
                        cic_used = True
                if (cic_used == False):
                    call.bicc_cic = i
                    break
            if (call.bicc_cic == 0):
                log.info("NO MORE CICs. EXITING!!!")
                sys.exit(0)
            call.bicc_parser.cic = call.bicc_cic
            call.bicc_builder.cic = call.bicc_cic

        if (bicc != None):
            fmt = 'IB'
            data = bicc[:struct.calcsize(fmt)]
            call.bicc_cic, call.bicc_msg_type = struct.unpack(fmt,data)
            call.bicc_parser.cic = call.bicc_cic
            call.bicc_builder.cic = call.bicc_cic
            call.bicc_parser.msg_type = call.bicc_msg_type
            call.sip_callid = ''.join(random.choice(string.ascii_lowercase) for i in range(10))

        activecalllist.append(call)

        log.info("Call created with call-id:%s and cic:%d" % (call.sip_callid, call.bicc_cic))
        return call

    def bycallid(self, sip_msg):
        global activecalllist
        callid = sip_msg.headers['call-id']
        for c in activecalllist:
            if (callid == c.sip_callid):
                resp = sip_msg
                c.sip_to = re.search('sip:(.+)@(.+)', resp.headers['to']).group(1)
                c.sip_from = re.search('sip:(.+)@(.+)', resp.headers['from']).group(1)
                c.sip_cseq = resp.headers['cseq']
                c.sip_callid = resp.headers['call-id']
                c.sip_branch = resp.headers['via'].split('=')[-1]
                c.sip_from_tag = resp.headers['from'].split('=')[-1] if 'tag' in resp.headers['from'] else 'from_tag'
                c.sip_to_tag = resp.headers['to'].split('=')[-1] if 'tag' in resp.headers['to'] else 'to_tag'
                c.sip_mycontact = str(c.sip_to) + '@' + str(options.source_ip) + ':' + str(options.source_port)
                try:
                    c.sip_remotecontact = resp.headers['contact'] 
                except:
                    c.sip_remotecontact = 'remote@contact'
                return c
        return callsession.createcall(sip=sip_msg) 

    def bycic(self, bicc_msg):
        global activecalllist
        cic = 0
        msg_type = 0
        try:
            fmt = 'IB'
            data = bicc_msg[:struct.calcsize(fmt)]
            cic, msg_type = struct.unpack(fmt,data)
        except Exception as e:
            log.info ("Invalid BICC msg|%s" % (str(e)))
            return None
        for c in activecalllist:
            if (cic == c.bicc_cic):
                c.bicc_parser.msg = bicc_msg
                c.bicc_parser.msg_type = msg_type
                c.bicc_builder.cic = cic
                c.bicc_msg_type = msg_type
                c.bicc_cic = cic
                return c
        return callsession.createcall(bicc=bicc_msg)


def canon_header(s):
    exception = {
        'call-id': 'Call-ID',
        'cseq': 'CSeq',
        'www-authenticate': 'WWW-Authenticate'
    }
    short = ['allow-events', 'u', 'call-id', 'i', 'contact', 'm', 'content-encoding', 'e',
        'content-length', 'l', 'content-type', 'c', 'event', 'o', 'from', 'f', 'subject', 's', 'supported', 'k', 'to', 't', 'via', 'v']
    s = s.lower()
    return ((len(s) == 1) and s in short and canon_header(short[short.index(s) - 1])) \
        or (s in exception and exception[s]) or '-'.join([x.capitalize() for x in s.split('-')])


def parse_headers(f):
        """Return dict of HTTP headers parsed from a file object."""
        d = {}
        while 1:
            line = f.readline().strip()
            if not line:
                break
            l = line.split(None, 1)
            if not l[0].endswith(':'):
                raise SipUnpackError('invalid header: %r' % line)
            k = l[0][:-1].lower()
            d[k] = len(l) != 1 and l[1] or ''
        return d


def parse_body(f, headers):
    """Return SIP body parsed from a file object, given HTTP header dict."""
    if 'content-length' in headers:
        n = int(headers['content-length'])
        body = f.read(n)
        if len(body) != n:
            raise SipNeedData('short body (missing %d bytes)' % (n - len(body)))
    elif 'content-type' in headers:
        body = f.read()
    else:
        body = ''
    return body


class Message:
    """SIP Protocol headers + body."""
    __metaclass__ = type
    __hdr_defaults__ = {}
    headers = None
    body = None

    def __init__(self, *args, **kwargs):
        if args:
            self.unpack(args[0])
        else:
            self.headers = {}
            self.body = ''
            for k, v in self.__hdr_defaults__.iteritems():
                setattr(self, k, v)
            for k, v in kwargs.iteritems():
                setattr(self, k, v)

    def unpack(self, buf):
        f = cStringIO.StringIO(buf)
        # Parse headers
        self.headers = parse_headers(f)
        # Parse body
        self.body = parse_body(f, self.headers)
        # Save the rest
        self.data = f.read()

    def pack_hdr(self):
        return ''.join(['%s: %s\r\n' % (canon_header(k), v) for k, v in self.headers.iteritems()])

    def __len__(self):
        return len(str(self))

    def __str__(self):
        return '%s\r\n%s' % (self.pack_hdr(), self.body)


class Request(Message):
        """SIP request."""
        __hdr_defaults__ = {
            'method': 'INVITE',
            'uri': 'sip:user@example.com',
            'version': '2.0',
            'headers': {'to': '', 'from': '', 'call-id': '', 'cseq': '', 'contact': ''}
        }
        __methods = dict.fromkeys((
            'ACK', 'BYE', 'CANCEL', 'INFO', 'INVITE', 'MESSAGE', 'NOTIFY',
            'OPTIONS', 'PRACK', 'PUBLISH', 'REFER', 'REGISTER', 'SUBSCRIBE',
            'UPDATE'
        ))
        __proto = 'SIP'

        def unpack(self, buf):
            f = cStringIO.StringIO(buf)
            line = f.readline()
            l = line.strip().split()
            if len(l) != 3 or l[0] not in self.__methods or not l[2].startswith(self.__proto):
                raise SipUnpackError('invalid request: %r' % line)
            self.method = l[0]
            self.uri = l[1]
            self.version = l[2][len(self.__proto) + 1:]
            Message.unpack(self, f.read())

        def __str__(self):
            return '%s %s %s/%s\r\n' % (self.method, self.uri, self.__proto,
                self.version) + Message.__str__(self)


class Response(Message):
    """SIP response."""

    __hdr_defaults__ = {
        'version': '2.0',
        'status': '200',
        'reason': 'OK',
        'headers': {'to': '', 'from': '', 'call-id': '', 'cseq': '', 'contact': ''}
    }
    __proto = 'SIP'

    def unpack(self, buf):
        f = cStringIO.StringIO(buf)
        line = f.readline()
        l = line.strip().split(None, 2)
        if len(l) < 2 or not l[0].startswith(self.__proto) or not l[1].isdigit():
            raise SipUnpackError('invalid response: %r' % line)
        self.version = l[0][len(self.__proto) + 1:]
        self.status = l[1]
        self.reason = l[2]
        Message.unpack(self, f.read())

    def __str__(self):
        return '%s/%s %s %s\r\n' % (self.__proto, self.version, self.status,
            self.reason) + Message.__str__(self)


def render_template(template, template_vars):
    for k in template_vars.keys():
        if k.startswith("."):
            template_vars[k] = eval(template_vars[k])
    try:
        if options.verbose:
            log.info("=======================================\n")
            log.info("I'm using these variables in templates: \n")
            log.info("=======================================\n")
            for k in template_vars.keys():
                log.info("%s: %s\n" % (k, template_vars[k]))
            log.info("=======================================\n\n")
        for key,value in template_vars.iteritems():
            template = re.sub(r'%%\(%s\)s'%(key),str(value),template) 
        #ret = template % template_vars
        ret = template
    except KeyError as e:
        log.info("ERROR: missing template variable. %s\n" % e)
        sys.exit(-1)
    except Exception as e:
        log.info("ERROR: error in template processing. %s\n" % e)
        sys.exit(-1)
    return ret


def gen_request(template_vars, options):
    try:
        req_list = list()
        for i in range(options.count):
            template_vars["seq"] = i
            for k in template_vars.keys():
                if k.startswith("."):
                    template_vars[k] = eval(template_vars[k])

            if options.request_template is None:
                request = render_template(def_request, template_vars)
            else:
                try:
                    f = open(options.request_template)
                    file_request = f.read()
                    f.close()
                    request = render_template(file_request, template_vars)
                except Exception as e:
                    log.info("ERROR: cannot open file %s. %s\n" % (options.request_template, e))
                    sys.exit(-1)
            try:
                req = Request(request)
            except SipUnpackError as e:
                #log.info("Malformed SIP Request. %s\n. Seems to be a response." % (e))
                req = Response(request)
            if "cseq" not in req.headers:
                req.headers["cseq"] = "%d %s" % (i, req.method)
            req_list.append(req)
    except Exception as e:
        log.info(str(e))
    return req_list


def open_sock(options):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setblocking(0)
        except Exception as e:
            log.info("ERROR: cannot create socket. %s\n" % e)
            sys.exit(-1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        if options.source_port:
            sock.bind((options.source_ip, options.source_port))
        sock.settimeout(options.wait)
        return sock


def sip_processor(resp, addr):
    global cs
    c = cs.bycallid(resp)
    if c == None:
        return
    c.udp_dest_ip = addr[0]
    c.udp_dest_port = addr[1]
    if resp.__class__.__name__ == "Response":
        if resp.status == "200":
            if "INVITE" in resp.headers['cseq']:
                options.request_template="ack.tmpl"
                options.var=['from_number:%s'%(c.sip_from),
                    'to_number:%s'%(c.sip_to),
                    'source_ip:%s'%(c.udp_source_ip),
                    'dest_ip:%s'%(c.udp_dest_ip),
                    'call-id:%s'%(c.sip_callid),
                    'cseq:%s'%(c.sip_cseq),
                    'source_port:%d'%(c.udp_source_port),
                    'dest_port:%d'%(c.udp_dest_port),
                    'call_branch:%s'%(c.sip_branch),
                    'from_tag:%s'%(c.sip_from_tag),
                    'to_tag:%s'%(c.sip_to_tag)]
                tp.push([create_and_send_sip,options,c])
                tp.push([c.bicc_builder.make_apm,resp.body])
                tp.push([c.bicc_builder.make_acm])
                tp.push([c.bicc_builder.make_anm])
            if "BYE" in resp.headers['cseq']:
                tp.push([c.bicc_builder.make_rlc])
    elif resp.__class__.__name__ == "Request":
        if resp.method == "ACK":
            pass
        if resp.method == "INFO":
            digit = resp.body.splitlines()[0].split('=')[-1]
            log.info("Received digit:%s in SIP INFO"%(digit))
            tp.push([c.bicc_builder.make_apm_dtmf_start,digit])
            tp.push([c.bicc_builder.make_apm_dtmf_stop])
            options.request_template="200-cseq-info.tmpl"
            options.var=['from_number:%s'%(c.sip_from),
                    'to_number:%s'%(c.sip_to),
                    'source_ip:%s'%(c.udp_source_ip),
                    'dest_ip:%s'%(c.udp_dest_ip),
                    'call-id:%s'%(c.sip_callid),
                    'cseq:%s'%(c.sip_cseq),
                    'source_port:%d'%(c.udp_source_port),
                    'dest_port:%d'%(c.udp_dest_port),
                    'call_branch:%s'%(c.sip_branch),
                    'from_tag:%s'%(c.sip_from_tag),
                    'to_tag:%s'%(c.sip_to_tag)]
            tp.push([create_and_send_sip,options,c])
        if resp.method == "CANCEL":
            options.request_template="200-cseq-cancel.tmpl"
            options.var=['from_number:%s'%(c.sip_from),
                    'to_number:%s'%(c.sip_to),
                    'source_ip:%s'%(c.udp_source_ip),
                    'dest_ip:%s'%(c.udp_dest_ip),
                    'call-id:%s'%(c.sip_callid),
                    'cseq:%s'%(c.sip_cseq),
                    'source_port:%d'%(c.udp_source_port),
                    'dest_port:%d'%(c.udp_dest_port),
                    'call_branch:%s'%(c.sip_branch),
                    'from_tag:%s'%(c.sip_from_tag),
                    'to_tag:%s'%(c.sip_to_tag)]
            tp.push([create_and_send_sip,options,c])
        if resp.method == "INVITE":
            tp.push([c.bicc_builder.make_iam,c.sip_from, 
                       c.sip_to, 
                       resp.body, 
                       options.source_ip])
            c.bicc_called = c.sip_to
            c.bicc_calling = c.sip_from
            options.request_template="100-trying.tmpl"
            options.var=['from_number:%s'%(c.sip_from),
                    'to_number:%s'%(c.sip_to),
                    'source_ip:%s'%(c.udp_source_ip),
                    'dest_ip:%s'%(c.udp_dest_ip),
                    'call-id:%s'%(c.sip_callid),
                    'cseq:%s'%(c.sip_cseq),
                    'source_port:%d'%(c.udp_source_port),
                    'dest_port:%d'%(c.udp_dest_port),
                    'call_branch:%s'%(c.sip_branch),
                    'from_tag:%s'%(c.sip_from_tag),
                    'to_tag:%s'%(c.sip_to_tag)]
            tp.push([create_and_send_sip,options,c])
        if resp.method == "BYE":
            options.request_template="200-cseq-bye.tmpl"
            options.var=['from_number:%s'%(c.sip_from),
                    'to_number:%s'%(c.sip_to),
                    'source_ip:%s'%(c.udp_source_ip),
                    'dest_ip:%s'%(c.udp_dest_ip),
                    'call-id:%s'%(c.sip_callid),
                    'cseq:%s'%(c.sip_cseq),
                    'source_port:%d'%(c.udp_source_port),
                    'dest_port:%d'%(c.udp_dest_port),
                    'call_branch:%s'%(c.sip_branch),
                    'from_tag:%s'%(c.sip_from_tag),
                    'to_tag:%s'%(c.sip_to_tag)]
            tp.push([create_and_send_sip,options,c])
            tp.push([c.bicc_builder.make_rel])
        if resp.method == "OPTIONS":
            options.request_template="200-cseq-options.tmpl"
            options.var=['from_number:%s'%(c.sip_from),
                    'to_number:%s'%(c.sip_to),
                    'source_ip:%s'%(c.udp_source_ip),
                    'dest_ip:%s'%(c.udp_dest_ip),
                    'call-id:%s'%(c.sip_callid),
                    'cseq:%s'%(c.sip_cseq),
                    'source_port:%d'%(c.udp_source_port),
                    'dest_port:%d'%(c.udp_dest_port),
                    'call_branch:%s'%(c.sip_branch),
                    'from_tag:%s'%(c.sip_from_tag),
                    'to_tag:%s'%(c.sip_to_tag)]
            tp.push([create_and_send_sip,options,c])

def create_and_send_sip(options, c):
    global udp_sock, sctp_sock, cs
    template_vars = dict()
   
   
    options.dest_ip = c.udp_dest_ip
    options.dest_port = c.udp_dest_port

    # first var is empty by default
    for v in options.var:
        try:
            key = v.split(":")[0]
            val = ":".join(v.split(":")[1:])
            template_vars.update({key: val})
        except IndexError:
            log.info("ERROR: variables must be in format name:value. %s\n" % v)
            opt.print_help()
            sys.exit()


    
    for req in gen_request(template_vars, options):
        try:
            sip_req  = req
            # Add Content-Lenght if missing
            if "content-length" not in sip_req.headers:
                sip_req.headers["content-length"] = len(sip_req.body)
            try:
                udp_sock.sendto(str(sip_req), (options.dest_ip, options.dest_port))
            except Exception as e:
                log.info("ERROR: cannot send packet to %s:%d. %s\n" % (options.dest_ip, options.dest_port, e))
            if options.verbose:
                if req.__class__.__name__ == "Request":
                    log.info("sent Request %s to %s:%d cseq=%s len=%d\n" % (sip_req.method, options.dest_ip, options.dest_port, sip_req.headers['cseq'].split()[0], len(str(sip_req))))
                if req.__class__.__name__ == "Response":
                    log.info("sent Response %s to %s:%d cseq=%s len=%d\n" % (sip_req.status, options.dest_ip, options.dest_port, sip_req.headers['cseq'].split()[0], len(str(sip_req))))
                if options.verbose:
                    log.info("\n%s\n" % sip_req)
        except socket.timeout:
            pass
        time.sleep(options.wait)


def main():
    global udp_sock, sctp_sock, cs
    while True:
        try:
            read = [udp_sock]
            inputready, outputready, exceptready = select.select(read, [], [], options.timeout)
            for s in inputready:
                if s == udp_sock:
                    buf = None
                    buf, addr = udp_sock.recvfrom(0xffff)
                    log.info ("\n" + buf + "\n")
                try:
                    resp = Response(buf)
                except SipUnpackError as e:
                    resp = Request(buf)
                sip_processor(resp,addr)
        except KeyboardInterrupt as e:
            log.info("KeyboardInterrupt")
            sys.exit(0)
        except Exception as e:
            log.info(str(e))
            pass



##GLOBALS##
udp_sock = None
sctp_sock = None
activecalllist = list()
cs = callsession()
tp = ThreadPool()
log = logger.get_logger()

##MAIN##
if __name__ == '__main__':
    try:
        sctp_sock = sctp_server(options.sctp_source_ip,options.sctp_source_port,sctp_cb) 
        udp_sock = open_sock(options)
    except Exception as e:
        log.info("ERROR: cannot open socket. %s\n" % e)
        sys.exit(-1)
    main()
