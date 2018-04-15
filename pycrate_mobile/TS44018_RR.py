# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.3
# *
# * Copyright 2017. Benoit Michau. ANSSI.
# *
# * This library is free software; you can redistribute it and/or
# * modify it under the terms of the GNU Lesser General Public
# * License as published by the Free Software Foundation; either
# * version 2.1 of the License, or (at your option) any later version.
# *
# * This library is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# * Lesser General Public License for more details.
# *
# * You should have received a copy of the GNU Lesser General Public
# * License along with this library; if not, write to the Free Software
# * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, 
# * MA 02110-1301  USA
# *
# *--------------------------------------------------------
# * File Name : pycrate_mobile/TS44018_RR.py
# * Created : 2017-07-20
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#------------------------------------------------------------------------------#
# 3GPP TS 44.018 GSM / EDGE RRC protocol
# release 13 (d60)
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from .TS24008_IE import *
from .TS24007    import *

#------------------------------------------------------------------------------#
# RRC header
# TS 44.018, section 
#------------------------------------------------------------------------------#

_RRC_dict = {
    0:'SYSTEM INFORMATION TYPE 13',
    1:'SYSTEM INFORMATION TYPE 14',
    2:'SYSTEM INFORMATION TYPE 2 bis',
    3:'SYSTEM INFORMATION TYPE 2 ter',
    4:'SYSTEM INFORMATION TYPE 9',
    5:'SYSTEM INFORMATION TYPE 5 bis',
    6:'SYSTEM INFORMATION TYPE 5 ter',
    7:'SYSTEM INFORMATION TYPE 2 quater',
    9:'VGCS UPLINK GRANT',
    10:'PARTIAL RELEASE',
    13:'CHANNEL RELEASE',
    14:'UPLINK RELEASE',
    15:'PARTIAL RELEASE COMPLETE',
    16:'CHANNEL MODE MODIFY',
    17:'TALKER INDICATION',
    18:'RR STATUS',
    19:'CLASSMARK ENQUIRY',
    20:'FREQUENCY REDEFINITION',
    21:'MEASUREMENT REPORT',
    22:'CLASSMARK CHANGE',
    #22:'MBMS ANNOUNCEMENT',
    23:'CHANNEL MODE MODIFY ACKNOWLEDGE',
    24:'SYSTEM INFORMATION TYPE 8',
    25:'SYSTEM INFORMATION TYPE 1',
    26:'SYSTEM INFORMATION TYPE 2',
    27:'SYSTEM INFORMATION TYPE 3',
    28:'SYSTEM INFORMATION TYPE 4',
    29:'SYSTEM INFORMATION TYPE 5',
    30:'SYSTEM INFORMATION TYPE 6',
    31:'SYSTEM INFORMATION TYPE 7',
    32:'NOTIFICATION/NCH',
    33:'PAGING REQUEST TYPE 1',
    34:'PAGING REQUEST TYPE 2',
    36:'PAGING REQUEST TYPE 3',
    38:'NOTIFICATION/RESPONSE',
    39:'PAGING RESPONSE',
    40:'HANDOVER FAILURE',
    41:'ASSIGNMENT COMPLETE',
    42:'UPLINK BUSY',
    43:'HANDOVER COMMAND',
    44:'HANDOVER COMPLETE',
    45:'PHYSICAL INFORMATION',
    46:'ASSIGNMENT COMMAND',
    47:'ASSIGNMENT FAILURE',
    48:'CONFIGURATION CHANGE COMMAND',
    49:'CONFIGURATION CHANGE ACK',
    50:'CIPHERING MODE COMPLETE',
    51:'CONFIGURATION CHANGE REJECT',
    52:'GPRS SUSPENSION REQUEST',
    53:'CIPHERING MODE COMMAND',
    54:'EXTENDED MEASUREMENT REPORT',
    54:'SERVICE INFORMATION',
    55:'EXTENDED MEASUREMENT ORDER',
    56:'APPLICATION INFORMATION',
    57:'IMMEDIATE ASSIGNMENT EXTENDED',
    58:'IMMEDIATE ASSIGNMENT REJECT',
    59:'ADDITIONAL ASSIGNMENT',
    61:'SYSTEM INFORMATION TYPE 16',
    62:'SYSTEM INFORMATION TYPE 17',
    63:'IMMEDIATE ASSIGNMENT',
    64:'SYSTEM INFORMATION TYPE 18',
    65:'SYSTEM INFORMATION TYPE 19',
    66:'SYSTEM INFORMATION TYPE 20',
    67:'SYSTEM INFORMATION TYPE 15',
    68:'SYSTEM INFORMATION TYPE 13 alt',
    69:'SYSTEM INFORMATION TYPE 2 n',
    70:'SYSTEM INFORMATION TYPE 21',
    72:'DTM ASSIGNMENT FAILURE',
    73:'DTM REJECT',
    74:'DTM REQUEST',
    75:'PACKET ASSIGNMENT',
    76:'DTM ASSIGNMENT COMMAND',
    77:'DTM INFORMATION',
    78:'PACKET NOTIFICATION',
    96:'UTRAN CLASSMARK CHANGE',
    98:'CDMA 2000 CLASSMARK CHANGE',
    99:'INTER SYSTEM TO UTRAN HANDOVER COMMAND',
    100:'INTER SYSTEM TO CDMA2000 HANDOVER COMMAND',
    101:'GERAN IU MODE CLASSMARK CHANGE',
    102:'PRIORITY UPLINK REQUEST',
    103:'DATA INDICATION',
    104:'DATA INDICATION 2'
    }

'''
Complete list of messages:

    Channel establishment messages:
ADDITIONAL ASSIGNMENT
IMMEDIATE ASSIGNMENT
IMMEDIATE PACKET ASSIGNMENT
IMMEDIATE ASSIGNMENT EXTENDED
IMMEDIATE ASSIGNMENT REJECT
DTM ASSIGMENT FAILURE
DTM REJECT
DTM REQUEST
PACKET ASSIGNMENT 
EC IMMEDIATE ASSIGNMENT TYPE 1
EC IMMEDIATE ASSIGNMENT TYPE 2
EC IMMEDIATE ASSIGNMENT REJECT
EC DOWNLINK ASSIGNMENT
EC PACKET CHANNEL REQUEST
    Ciphering messages:
CIPHERING MODE COMMAND
CIPHERING MODE COMPLETE
    Handover messages:
ASSIGNMENT COMMAND
ASSIGNMENT COMPLETE
ASSIGNMENT FAILURE
DTM ASSIGMENT COMMAND
INTER SYSTEM TO UTRAN HANDOVER COMMAND
HANDOVER ACCESS
HANDOVER COMMAND
HANDOVER COMPLETE
HANDOVER FAILURE
PHYSICAL INFORMATION
INTER SYSTEM TO CDMA2000 HANDOVER COMMAND
INTER SYSTEM TO E-UTRAN HANDOVER COMMAND
    Channel release messages:
CHANNEL RELEASE
PARTIAL RELEASE
PARTIAL RELEASE COMPLETE
    Paging messages:
PACKET NOTIFICATION
PAGING REQUEST TYPE 1
PAGING REQUEST TYPE 2
PAGING REQUEST TYPE 3
PAGING RESPONSE
EC DUMMY
EC PAGING REQUEST
    System information messages:
SYSTEM INFORMATION TYPE 1
SYSTEM INFORMATION TYPE 2
SYSTEM INFORMATION TYPE 2bis
SYSTEM INFORMATION TYPE 2ter
SYSTEM INFORMATION TYPE 2quater
SYSTEM INFORMATION TYPE 2n
SYSTEM INFORMATION TYPE 3
SYSTEM INFORMATION TYPE 4
SYSTEM INFORMATION TYPE 5
SYSTEM INFORMATION TYPE 5bis
SYSTEM INFORMATION TYPE 5ter
SYSTEM INFORMATION TYPE 6
SYSTEM INFORMATION TYPE 7
SYSTEM INFORMATION TYPE 8
SYSTEM INFORMATION TYPE 9
SYSTEM INFORMATION TYPE 10
SYSTEM INFORMATION TYPE 10bis
SYSTEM INFORMATION TYPE 10ter
SYSTEM INFORMATION TYPE 13
SYSTEM INFORMATION TYPE 13alt
SYSTEM INFORMATION TYPE 14
SYSTEM INFORMATION TYPE 15
SYSTEM INFORMATION TYPE 16
SYSTEM INFORMATION TYPE 17
SYSTEM INFORMATION TYPE 18
SYSTEM INFORMATION TYPE 19
SYSTEM INFORMATION TYPE 20
SYSTEM INFORMATION TYPE 21
SYSTEM INFORMATION TYPE 22
SYSTEM INFORMATION TYPE 23
EC SYSTEM INFORMATION TYPE 1
EC SYSTEM INFORMATION TYPE 2
EC SYSTEM INFORMATION TYPE 3
EC SYSTEM INFORMATION TYPE 4
DTM INFORMATION
    Specific messages for VBS/VGCS:
NOTIFICATION/FACCH
NOTIFICATION/NCH
NOTIFICATION RESPONSE
VBS/VGCS RECONFIGURE
VBS/VGCS RECONFIGURE2
TALKER INDICATION
UPLINK ACCESS
UPLINK BUSY
UPLINK FREE
UPLINK RELEASE
VGCS UPLINK GRANT
PRIORITY UPLINK REQUEST
VGCS Neighbour Cell Information
DATA INDICATION
DATA INDICATION 2
NOTIFY APPLICATION DATA
    Measurement specific messages:
EXTENDED MEASUREMENT ORDER
EXTENDED MEASUREMENT REPORT
MEASUREMENT REPORT
MEASUREMENT INFORMATION
ENHANCED MEASUREMENT REPORT
    Miscellaneous messages:
CHANNEL MODE MODIFY
CHANNEL MODE MODIFY ACKNOWLEDGE
CHANNEL REQUEST
CLASSMARK CHANGE
CLASSMARK ENQUIRY
UTRAN CLASSMARK CHANGE
cdma2000 CLASSMARK CHANGE
GERAN IU MODE CLASSMARK CHANGE
FREQUENCY REDEFINITION
SYNCHRONIZATION CHANNEL INFORMATION
COMPACT SYNCHRONIZATION CHANNEL INFORMATION
EC-SCH INFORMATION
RR STATUS
GPRS SUSPENSION REQUEST
    Configuration Change messages:
CONFIGURATION CHANGE COMMAND
CONFIGURATION CHANGE ACKNOWLEDGE
CONFIGURATION CHANGE REJECT
    Application messages:
APPLICATION INFORMATION
'''

class RRHeader(Envelope):
    _GEN = (
        Uint('SkipInd', bl=4),
        Uint('ProtDisc', val=6, bl=4, dic=ProtDisc_dict),
        Uint('Type', bl=8, dic=_RRC_dict),
        )

#------------------------------------------------------------------------------#
# PAGING RESPONSE
# TS 44.018, section 9.1.25
#------------------------------------------------------------------------------#

class RRPagingResponse(Envelope):
    _GEN = (
        RRHeader(val={'Type':39}),
        Uint('spare', bl=4),
        Type1V('CKSN', dic=CKSN_dict),
        Type4LV('MSCm2', val={'V':b'@\x00\x00'}, IE=MSCm2()),
        Type4LV('ID', val={'V':b'\xf4\0\0\0\0'}, IE=ID()),
        Type1TV('AddUpdateParams', val={'T':0xC, 'V':0}, IE=AddUpdateParams())
        )

#------------------------------------------------------------------------------#
# RRC dispatcher
#------------------------------------------------------------------------------#

RRTypeClasses = {
    39 : RRPagingResponse,
    }

def get_rr_msg_instances():
    return {k: RRTypeClasses[k]() for k in RRTypeClasses}

