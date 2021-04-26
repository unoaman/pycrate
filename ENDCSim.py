#!/usr/bin/env python3
import sys
import time

from pycrate_corenet import ENDCServer
from pycrate_corenet import HdlrENB 
   
HdlrENB.ENBd.TRACE_ASN_S1AP = True
HdlrENB.ENBd.TRACE_ASN_X2AP = True

ENDCServer.ENDCX2Server.SERVER_ENB['IP'] = '10.12.111.250'

epc = ENDCServer.ENDCX2Server()


