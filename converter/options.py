#!/usr/bin/python
# -*- coding: UTF-8 -*-
# -*- Mode: Python -*-

__author__ = 'Divyanshu Chauhan <divyanshu0045@gmail.com>'
__date__ = '04 Jun 2019'

import sys

class options:
    count=1 #No of times SIP message has to be repeated
    wait=1 #Minimum delay between 2 SIP Packets
    timeout=1 #Minimum wait time for SIP reply
    var=[] #variables for template
    verbose=True #if true, print template variables and outgoing sip packets
    source_ip="10.18.0.41" #converter sip/udp ip
    source_port=5061 #converter sip/udp port
    dest_ip="10.0.230.46" #sip phone udp ip
    dest_port=5060 #sip phone udp port
    sctp_dest_ip="172.16.30.27" #bicc dialer sctp ip
    sctp_dest_port=6003 #bicc dialer sctp port 
    sctp_source_ip="10.18.0.41" #converter bicc/sctp ip
    sctp_source_port=8000 #converter bicc/sctp port
    request_template=None #template name of sip packet
    logfile='logfile' #name of logfile
    console_log=False #print logs on console
    default_sdp_ip="172.16.30.27" #media ip sent to sip dialer if not received from bicc dialer
    default_sdp_port=60000 #media port sent to sip dialer if not received from bicc dialer
    first_cic=1 #starting cic for bicc dialer
    last_cic=10000 #last cic for bicc dialer
    worker_threads=100 #no. of worker threads
    detailed_log=False #print file,function and line
