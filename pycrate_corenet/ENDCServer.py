# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2017. Benoit Michau. ANSSI.
# * Copyright 2020. Benoit Michau. P1Sec.
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
# * File Name : pycrate_corenet/ENDCServer
# * Created : 2020-08-10
# * Authors : Dashrath Mahto
# *--------------------------------------------------------
#*/

#------------------------------------------------------------------------------#
# This is the ENDC server
# 
# It serves endc connection to:
# - eNodeB and gNodeB over X2AP
# 
# It handles 5G NSA ENDC signalling trafic for 5G NSA UE
# and connects them to specific GTPU
#------------------------------------------------------------------------------#

from .utils      import *
from .HdlrENB    import ENBd


# to log all the SCTP socket send() / recv() calls
DEBUG_SK = True


class ENDCX2Server(object):
    """Complete control-plane and user-plane server to handle:
    - eNodeB, over X2AP
    """
    
    #--------------------------------------------------------------------------#
    # debug and tracing level
    #--------------------------------------------------------------------------#
    #
    # verbosity level: list of log types to display when calling self._log(logtype, msg)
    DEBUG    = ('ERR', 'WNG', 'INF', 'DBG')
    # to log SCTP socket send() / recv() content
    TRACE_SK = True
    
    #--------------------------------------------------------------------------#
    # network server settings
    #--------------------------------------------------------------------------#
    #
    # SCTP sockets recv() buffer length
    SERVER_BUFLEN = 16384
    SERVER_MAXCLI = 16
    #
    # X2AP server
    SERVER_ENB = {'INET'  : socket.AF_INET,
                  'IP'    : '10.2.1.1',
                  'port'  : 36422,
                  'MAXCLI': SERVER_MAXCLI,
                  'errclo': True,
                  'GTPU'  : '10.2.1.1'}
    #SERVER_ENB = {} # disabling ENB ENDC X2AP server
    SERVER_GNB = {} # disabling GNB ENDC X2AP server
    #SERVER_GNB = {'INET'  : socket.AF_INET,
    #              'IP'    : '10.2.1.1',
    #              'port'  : 36422,
    #              'MAXCLI': SERVER_MAXCLI,
    #              'errclo': True,
    #              'GTPU'  : '10.2.1.1'}

    #
    #
    # Server scheduler resolution:
    # This is the timeout on the main select() loop.
    SCHED_RES = 0.1
    
    #--------------------------------------------------------------------------#
    # corenet global config parameters
    #--------------------------------------------------------------------------#
    #
    # main PLMN served
    PLMN = '00101'
    
    #--------------------------------------------------------------------------#
    # HNB, ENB and GNB parameters
    #--------------------------------------------------------------------------#
    #
    # Connection from RAN equipments:
    # Home-NodeB, eNodeB and gNodeB indexed by their global ID
    # (PLMN, CellId) for home-NodeB and eNodeB
    # (PLMN, CellType, CellId) for gNodeB
    # the RAN dict can be initialized with {(PLMN, *Cell*): None} here
    # this provides a whitelist of allowed basestations.
    RAN = {}
    #
    # Otherwise, this is a flag to allow any RAN equipment to connect the server
    # in case its PLMN is in the RAN_ALLOWED_PLMN list.
    # If enabled, RAN dict will be populated at runtime
    # If disabled, RAN keys (PLMN, *Cell*) needs to be setup by configuration (see above)
    RAN_CONNECT_ANY = True
    #
    # This is the list of accepted PLMN for RAN equipment connecting, 
    # when RAN_CONNECT_ANY is enabled
    RAN_ALLOWED_PLMN = [PLMN, '00107']
    #
    # lookup dict to get the set of RAN ids (PLMN, CellId) that serves a given
    # LAI, RAI and TAI
    LAI = {}
    RAI = {}
    TAI = {}
    
    # UE, indexed by IMSI, and their UEd handler instance
    UE = {}
    # UE, indexed by TMSI when the IMSI is unknown (at attachment), 
    # and their UEd handler instance are set in ._UEpre, created at init
    #
    # TMSI / P-TMSI / M-TMSI to IMSI conversion
    TMSI  = {}
    PTMSI = {}
    MTMSI = {}
   
    #--------------------------------------------------------------------------#
    # logging and init methods
    #--------------------------------------------------------------------------#
    
    def _log(self, logtype, msg):
        """Server logging facility
        
        DEBUG logtype: 'ERR', 'WNG', 'INF', 'DBG'
        TRACE logtype: 'TRACE_SK_[UL|DL]',
                       'TRACE_ASN_[X2AP|NGAP]_[UL|DL]',
        """
        if logtype[:3] == 'TRA':
            if logtype[6:8] == 'SK':
                log('[TRA] [%s]\n%s%s%s'\
                    % (logtype[6:], TRACE_COLOR_START, hexlify(msg).decode('ascii'), TRACE_COLOR_END))
            else:
                log('[TRA] [%s]\n%s%s%s'\
                    % (logtype[6:], TRACE_COLOR_START, msg, TRACE_COLOR_END))
        elif logtype in self.DEBUG:
            log('[%s] %s' % (logtype, msg))
    
    def __init__(self, serving=True, threaded=True):
        # initialize the Python built-in Mersennes Twister LFSR for producing TMSI
        random.seed(random.SystemRandom().randint(0, 1<<64))
        # starting the server in background
        self._running = False
        if threaded:
            self._server = threadit(self.start, serving=serving)
        else:
            self.start(serving=serving)
    
    #--------------------------------------------------------------------------#
    # SCTP socket server
    #--------------------------------------------------------------------------#
    
    def start(self, serving=True):
        #
        if DEBUG_SK:
            self._skc   = []
        # LUT for connected SCTP client and ENBId / HNBId
        self.SCTPCli    = {}
        #
        # start SCTP servers, bind() and listen()
        self._start_server()
        #
        if serving:
            # serve connections
            self._serve()
            # self._running has been set to False, main loop exited
            self._log('INF', 'SCTP server stopped')
    
    def is_running(self):
        return self._running
    
    def _start_server(self):
        self.SCTPServ = []
        for (cfg, attr) in ((self.SERVER_GNB, '_sk_gnb'),
                            (self.SERVER_ENB, '_sk_enb')):
            if 'INET' not in cfg or 'IP' not in cfg \
            or 'port' not in cfg or 'MAXCLI' not in cfg:
                setattr(self, attr, None)
                continue
            #
            try:
                sk   = sctp.sctpsocket_tcp(cfg['INET'])
                addr = (cfg['IP'], cfg['port'])
                srv  = attr[-3:].upper()
                self.sctp_set_events(sk)
            except Exception as err:
                raise(CorenetErr('cannot create SCTP socket: %s' % err))
            try:
                sk.bind(addr)
            except Exception as err:
                raise(CorenetErr('cannot bind SCTP socket on addr %r: %s' % (addr, err)))
            try:
                sk.listen(cfg['MAXCLI'])
            except Exception as err:
                raise(CorenetErr('cannot listen to SCTP connection: {1}'.format(err)))
            #
            self._log('INF', 'SCTP %s server started on address %r' % (srv, addr))
            setattr(self, attr, sk)
            self.SCTPServ.append(sk)
        #
        self.SCTPServ = tuple(self.SCTPServ)
    
    def _serve(self):
        # Main server loop, using select() to read sockets, the loop:
        # gets new SCTP clients,
        # gets new SCTP streams for connected SCTP clients,
        # and eventually timeouts running UE NAS procedures
        self._running, T0 = True, time()
        while self._running:
            skr = []
            try:
                skr = select(self.SCTPServ + tuple(self.SCTPCli), (), (), self.SCHED_RES)[0]
                #self._log('INF', 'SCTP out of select')
            except Exception as err:
                self._log('ERR', 'select() error: %s' % err)
                self._running = False
            #
            for sk in skr:
                if sk == self._sk_enb:
                    self._log('INF', 'SCTP new ENDC X2 peer connection request')
                    # new ENDC eNodeB STCP client (ENDCX2SetupRequest)
                    self.handle_new_enb()
                else:
                    # read from connected SCTP client for a new stream 
                    # (whatever PDU)
                    self._log('INF', 'SCTP new ENDC X2 peer message recived in connected state')
                    self.handle_stream_msg(sk)
    
    def stop(self):
        self._running = False
        asn_s1ap_release()
        sleep(self.SCHED_RES + 0.01)
        if self._sk_enb is not None:
            self._sk_enb.close()
        #
        # disconnect all RAN clients
        for cli in self.SCTPCli:
            cli.close()
            self.RAN[self.SCTPCli[cli]].disconnect()
        self.SCTPCli.clear()
        #
    
    def sctp_handle_notif(self, sk, notif):
        self._log('DBG', 'SCTP notification: type %i, flags %i' % (notif.type, notif.flags))
        # TODO
    
    def sctp_set_events(self, sk):
        # configure the SCTP socket to receive adaptation layer and stream id
        # indications in sctp_recv() notification
        sk.events.data_io          = True
        sk.events.adaptation_layer = True
        #sk.events.association      = True
        sk.events.flush()
    
    #--------------------------------------------------------------------------#
    # SCTP stream handler
    #--------------------------------------------------------------------------#
    
    def _read_sk(self, sk):
        # we always arrive there after a select() call, 
        # hence, recv() should always return straight without blocking
        # TODO: loop on recv() to get the complete stream (in case of very long PDU...), 
        # then defragment those PDUs properly
        # TODO: in case notif has only 0, specific events need to be subscribed 
        # to get at least ppid and stream
        try:
            addr, flags, buf, notif = sk.sctp_recv(self.SERVER_BUFLEN)
        except TimeoutError as err:
            # the client disconnected
            if sk in self.SCTPCli:
                self._rem_sk(sk)
                return None, None
        except ConnectionError as err:
            # something went bad with the endpoint
            self._log('ERR', 'sctp_recv() failed, err: {0}'.format(err))
            if sk in self.SCTPCli:
                self._rem_sk(sk)
                return None, None
        if DEBUG_SK:
            self._skc.append( ('recv', time(), addr, flags, buf, notif) )
        if not buf:
            if flags & sctp.FLAG_NOTIFICATION:
                # SCTP notification
                self.sctp_handle_notif(sk, notif)
            elif sk in self.SCTPCli:
                # the client just disconnected
                self._rem_sk(sk)
        else:
            if self.TRACE_SK:
                self._log('TRACE_SK_UL', buf)
            if not flags & sctp.FLAG_EOR:
                self._log('WNG', 'SCTP message truncated') 
        return buf, notif
    
    def _rem_sk(self, sk):
        # close socket
        sk.close()
        # select RAN client
        cli = self.RAN[self.SCTPCli[sk]]
        if isinstance(cli, ENBd):
            self._log('DBG', 'eNB %r closed connection' % (cli.ID,))
            # remove from the Server location tables
            if cli.Config:
                self._unset_enb_loc(cli)
        else:
            assert()
        # update HNB / ENB state
        cli.disconnect()
        # update list of clients socket, and dict of RAN clients
        del self.SCTPCli[sk]
    
    def _write_sk(self, sk, buf, ppid=0, stream=0):
        if self.TRACE_SK:
            self._log('TRACE_SK_DL', buf)
        if ppid:
            ppid = htonl(ppid)
        #if stream:
        #    stream = htonl(stream)
        ret = 0
        try:
            ret = sk.sctp_send(buf, ppid=ppid, stream=stream)
        except Exception as err:
            self._log('ERR', 'cannot send buf to SCTP client at address %r' % (sk.getpeername(), ))
            if DEBUG_SK:
                self._skc.append( ('send', time(), buf, ppid, stream, err) )
        else:
            if DEBUG_SK:
                self._skc.append( ('send', time(), buf, ppid, stream) )
        return ret
    
    def handle_stream_msg(self, sk):
        buf, notif = self._read_sk(sk)
        if not buf:
            # WNG: it may be required to handle SCTP notifications, at some point...
            return
        # getting SCTP ppid, stream id and eNB/HNB handler
        ppid, sid, ranid = ntohl(notif.ppid), notif.stream, self.SCTPCli[sk]
        ran = self.RAN[ranid]
        #
        if ppid == SCTP_PPID_X2AP:
            assert( isinstance(ran, ENBd) )
            enb = ran
            if not asn_x2ap_acquire():
                enb._log('ERR', 'unable to acquire the X2AP module')
                return
            try:
                PDU_X2AP.from_aper(buf)
            except Exception:
                asn_x2ap_release()

                enb._log('WNG', 'invalid X2AP PDU transfer-syntax: %s'\
                         % hexlify(buf).decode('ascii'))
                Err = enb.init_s1ap_proc(S1APErrorIndNonUECN,
                                         Cause=('protocol', 'transfer-syntax-error'))
                pdu_tx = Err.send()
            else:
                pdu_rx = PDU_X2AP()
                if enb.TRACE_ASN_X2AP:
                    enb._log('TRACE_ASN_X2AP_UL', PDU_X2AP.to_asn1())
                self._log('ERR', '************* Dash Debug ')
                asn_x2ap_release()
                if sid == enb.SKSid:
                    # non-UE-associated signalling
                    self._log('INF', 'NON UE ENDC Msg received')
                    pdu_tx = enb.process_s1ap_pdu(pdu_rx)
                else:
                    # UE-associated signalling
                    self._log('INF', 'UE ENDC Msg received')
                    pdu_tx = enb.process_s1ap_ue_pdu(pdu_rx, sid)
            for pdu in pdu_tx:
                self.send_x2ap_pdu(enb, pdu, sid)
        #
        else:
            self._log('ERR', 'invalid SCTP PPID, %i' % ppid)
            return
    
    def send_x2ap_pdu(self, enb, pdu, sid):
        if not asn_x2ap_acquire():
            enb._log('ERR', 'unable to acquire the X2AP module')
            return
        PDU_X2AP.set_val(pdu)
        if enb.TRACE_ASN_S1AP:
            enb._log('TRACE_ASN_X2AP_DL', PDU_X2AP.to_asn1())
        buf = PDU_X2AP.to_aper()
        asn_x2ap_release()
        return self._write_sk(enb.SK, buf, ppid=SCTP_PPID_X2AP, stream=sid)
    
    #--------------------------------------------------------------------------#
    # eNodeB connection (4G)
    #--------------------------------------------------------------------------#
    
    def _parse_endcX2setup(self, pdu):
        if pdu[0] != 'initiatingMessage' or pdu[1]['procedureCode'] != 36:
            # not initiating / ENDCX2SetupRequest
            self._log('WNG', 'invalid X2AP PDU for setting up the eNB X2AP link')
            return
        #
        pIEs, plmn, cellid = pdu[1]['value'][1], None, None
        IEs = pIEs['protocolIEs']
        if 'protocolExtensions' in pIEs:
            Exts = pIEs['protocolExtensions']
        else:
            Exts = []
        for ie in IEs:
            if ie['id'] == 59:
                # Global-ENB-ID
                globenbid = ie['value'][1]
                plmn      = globenbid['pLMNidentity']
                cellid    = globenbid['eNB-ID'][1] # both macro / home eNB-ID are BIT STRING
                break
        if plmn is None or cellid is None:
            self._log('WNG', 'invalid S1AP PDU for setting up the eNB S1AP link: '\
                      'missing PLMN and CellID')
            return
        # decode PLMN and CellID
        try:
            PLMN   = plmn_buf_to_str(plmn)
            CellID = cellid_bstr_to_str(cellid)
            return PLMN, CellID
        except Exception:
            return None
    
    def _send_s1setuprej(self, sk, cause):
        IEs = [{'criticality': 'ignore',
                'id': 2, # id-Cause
                'value': (('S1AP-IEs', 'Cause'), cause)}]
        pdu = ('unsuccessfulOutcome',
               {'criticality': 'ignore',
                'procedureCode': 17,
                'value': (('S1AP-PDU-Contents', 'S1SetupFailure'),
                          {'protocolIEs' : IEs})})
        if not asn_s1ap_acquire():
            self._log('ERR', 'unable to acquire the S1AP module')
        else:
            PDU_S1AP.set_val(pdu)
            if ENBd.TRACE_ASN_S1AP:
                self._log('TRACE_ASN_S1AP_DL', PDU_S1AP.to_asn1())
            self._write_sk(sk, PDU_S1AP.to_aper(), ppid=SCTP_PPID_S1AP, stream=0)
            asn_s1ap_release()
        if self.SERVER_ENB['errclo']:
            sk.close()
    
    def handle_new_enb(self):
        sk, addr = self._sk_enb.accept()
        self._log('DBG', 'New eNB client from address %r' % (addr, ))
        #
        buf, notif = self._read_sk(sk)
        if not buf:
            # WNG: maybe required to handle SCTP notification, at some point
            return
        # verifying SCTP Payload Protocol ID and setting stream ID for 
        # non-UE-associated trafic
        ppid, sid = ntohl(notif.ppid), notif.stream
        if ppid != SCTP_PPID_X2AP:
            self._log('ERR', 'invalid X2AP PPID, %i' % ppid)
            if self.SERVER_ENB['errclo']:
                sk.close()
            return
        #
        if not asn_x2ap_acquire():
            self._log('ERR', 'unable to acquire the X2AP module')
            return
        try:
            PDU_X2AP.from_aper(buf)
        except Exception:
            self._log('WNG', 'invalid X2AP PDU transfer-syntax: %s'\
                      % hexlify(buf).decode('ascii'))
            # return nothing, no need to bother
            return
        if ENBd.TRACE_ASN_S1AP:
            self._log('TRACE_ASN_X2AP_UL', PDU_X2AP.to_asn1())
        pdu_rx = PDU_X2AP()
        asn_x2ap_release()
        #
        #ENBId = self._parse_endcX2setup(pdu_rx)
        ENBId = ('00107', '9752')
        if ENBId is None:
            # send S1SetupReject
        #    self._send_s1setuprej(sk, cause=('protocol', 'abstract-syntax-error-reject'))
            return
        elif ENBId not in self.RAN:
            if not self.RAN_CONNECT_ANY:
                self._log('ERR', 'eNB %r not allowed to connect' % (ENBId, ))
                # send S1SetupReject
        #        self._send_s1setuprej(sk, cause=('radioNetwork', 'unspecified'))
                return
            elif ENBId[0] not in self.RAN_ALLOWED_PLMN:
                self._log('ERR', 'eNB %r not allowed to connect, bad PLMN' % (ENBId, ))
        #        self._send_s1setuprej(sk, cause=('radioNetwork', 'unspecified'))
                return
            else:
                # creating an entry for this eNB
                enb = ENBd(self, sk, sid)
                self.RAN[ENBId] = enb
        else:
            if self.RAN[ENBId] is None:
                # eNB allowed, but not yet connected
                enb = ENBd(self, sk, sid)
                self.RAN[ENBId] = enb
            elif not self.RAN[ENBId].is_connected():
                # eNB already connected and disconnected in the past
                enb = self.RAN[ENBId]
                enb.__init__(self, sk, sid)
            else:
                # eNB already connected
                self._log('ERR', 'eNB %r already connected from address %r'\
                          % (ENBId, self.RAN[ENBId].SK.getpeername()))
                if self.SERVER_ENB['errclo']:
                    sk.close()
                return
        #
        ## process the initial PDU
        #pdu_tx = enb.process_s1ap_pdu(pdu_rx)
        # keep track of the client
        self.SCTPCli[sk] = ENBId
        ## add the enb TAI to the Server location tables
        #    self._set_enb_loc(enb)
        #
        #if enb.Config:
        # send available PDU(s) back
        if not asn_x2ap_acquire():
           self._log('ERR', 'unable to acquire the X2AP module')
           return
        pdu_tx = []
        endcx2setup_response_txt = open('./msg_template/ENDCX2SetupResponse.txt', 'r').read()
        #PDU_ENDC_X2_SETUP_FROM_TXT = X2AP.X2AP_PDU_Descriptions.X2AP_PDU
        #PDU_ENDC_X2_SETUP_FROM_TXT.from_asn1(endcx2setup_response_txt)
        #PDU_X2AP = PDU_ENDC_X2_SETUP_FROM_TXT 
        #if ENBd.TRACE_ASN_S1AP:
        #    enb._log('TRACE_ASN_S1AP_DL', PDU_X2AP.to_asn1())
        #self._write_sk(sk, PDU_X2AP.to_aper(), ppid=SCTP_PPID_X2AP, stream=sid)
        PDU_ENDC_X2_SETUP_FROM_TXT = X2AP.X2AP_PDU_Descriptions.X2AP_PDU
        PDU_ENDC_X2_SETUP_FROM_TXT.from_asn1(endcx2setup_response_txt)
        pdu_tx.append(PDU_ENDC_X2_SETUP_FROM_TXT())

        #sgnb add
        sgnb_add_response_tx = open('./msg_template/SGNBAddRequest_2qci.txt', 'r').read()
        PDU_SGNB_ADD_FROM_TXT = X2AP.X2AP_PDU_Descriptions.X2AP_PDU
        PDU_SGNB_ADD_FROM_TXT.from_asn1(sgnb_add_response_tx)
        pdu_tx.append(PDU_SGNB_ADD_FROM_TXT())

        for pdu in pdu_tx:
            PDU_X2AP.set_val(pdu)
            if ENBd.TRACE_ASN_S1AP:
                self._log('TRACE_ASN_X2AP_DL', PDU_X2AP.to_asn1())
            self._write_sk(sk, PDU_X2AP.to_aper(), ppid=SCTP_PPID_X2AP, stream=sid)
        asn_x2ap_release()
