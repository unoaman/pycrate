# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.3
# *
# * Copyright 2018. Benoit Michau. ANSSI.
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
# * File Name : pycrate_csn1dir/cell_selection_indicator_after_release_of_all_tch_and_sdcch_value_part.py
# * Created : 2018-07-30
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/
# specification: TS 44.018 - d80
# section: 10.5.2.1e Cell selection indicator after release of all TCH and SDCCH IE
# top-level object: Cell Selection Indicator after release of all TCH and SDCCH value part

# manual edit
# table 9.1.54.1a
_TransP = {
    0 : 0,
    1 : 10,
    2 : 19,
    3 : 28,
    4 : 36,
    5 : 44,
    6 : 52,
    7 : 60,
    8 : 67,
    9 : 74,
    10: 81,
    11: 88,
    12: 95,
    13: 102,
    14: 109,
    15: 116,
    16: 122
    }

def trans_p(n):
    try:
        return _TransP[n]
    except:
        return 0

# table 9.1.54.1b
_TransQ = {
    0 : 0,
    1 : 9,
    2 : 17,
    3 : 25,
    4 : 32,
    5 : 39,
    6 : 46,
    7 : 53,
    8 : 59,
    9 : 65,
    10: 71,
    11: 77,
    12: 83,
    13: 89,
    14: 95,
    15: 101,
    16: 106,
    17: 111,
    18: 116,
    19: 121,
    20: 126
    }

def trans_q(n):
    try:
        return _TransQ[n]
    except:
        return 0

# external references
from pycrate_csn1dir.pcid_group_ie import pcid_group_ie

# code automatically generated by pycrate_csn1
# change object type with type=CSN1T_BSTR (default type is CSN1T_UINT) in init
# add dict for value interpretation with dic={...} in CSN1Bit init
# add dict for key interpretation with kdic={...} in CSN1Alt init

from pycrate_csn1.csnobj import *

gsm_description_struct = CSN1List(name='gsm_description_struct', list=[
  CSN1Bit(name='band_indicator'),
  CSN1Bit(name='arfcn', bit=10),
  CSN1Bit(name='bsic', bit=6)])

e_utran_description_struct = CSN1List(name='e_utran_description_struct', list=[
  CSN1Bit(name='earfcn', bit=16),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Bit(name='measurement_bandwidth', bit=3)])}),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Ref(name='not_allowed_cells', obj=pcid_group_ie)])}),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Bit(name='target_pcid', bit=9)])})])

utran_tdd_description_struct = CSN1List(name='utran_tdd_description_struct', list=[
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Bit(name='bandwidth_tdd', bit=3)])}),
  CSN1Bit(name='tdd_arfcn', bit=14),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Bit(name='tdd_indic0'),
    CSN1Bit(name='nr_of_tdd_cells', bit=5),
    #CSN1Bit(name='tdd_cell_information_field', bit=('# unprocessed: (q(NR_OF_TDD_CELLS))', lambda: 0))])})])
    CSN1Bit(name='tdd_cell_information_field', bit=([2], trans_q))])})])

utran_fdd_description_struct = CSN1List(name='utran_fdd_description_struct', list=[
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Bit(name='bandwidth_fdd', bit=3)])}),
  CSN1Bit(name='fdd_arfcn', bit=14),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Bit(name='fdd_indic0'),
    CSN1Bit(name='nr_of_fdd_cells', bit=5),
    #CSN1Bit(name='fdd_cell_information_field', bit=('# unprocessed: (p(NR_OF_FDD_CELLS))', lambda: 0))])})])
    CSN1Bit(name='fdd_cell_information_field', bit=([2], trans_p))])})])

cell_selection_indicator_after_release_of_all_tch_and_sdcch_value_part = CSN1Alt(name='cell_selection_indicator_after_release_of_all_tch_and_sdcch_value_part', alt={
  '000': ('', [
  CSN1List(num=-1, list=[
    CSN1Val(name='', val='1'),
    CSN1Ref(name='gsm_description', obj=gsm_description_struct)]),
  CSN1Val(name='', val='0')]),
  '001': ('', [
  CSN1List(num=-1, list=[
    CSN1Val(name='', val='1'),
    CSN1Ref(name='utran_fdd_description', obj=utran_fdd_description_struct)]),
  CSN1Val(name='', val='0')]),
  '010': ('', [
  CSN1List(num=-1, list=[
    CSN1Val(name='', val='1'),
    CSN1Ref(name='utran_tdd_description', obj=utran_tdd_description_struct)]),
  CSN1Val(name='', val='0')]),
  '011': ('', [
  CSN1List(num=-1, list=[
    CSN1Val(name='', val='1'),
    CSN1Ref(name='e_utran_description', obj=e_utran_description_struct)]),
  CSN1Val(name='', val='0')])})
