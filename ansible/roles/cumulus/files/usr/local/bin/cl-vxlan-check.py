#!/usr/bin/python

import os
import sys
import re
import subprocess
import exceptions
import optparse
from sets import Set

BCMCMD             = '/usr/lib/cumulus/bcmcmd'
PORTTAB            = '/var/lib/cumulus/porttab'
VLAN_CFG           = '/proc/net/vlan/config'
BRIDGE_ROOT        = '/sys/class/net/'

DEBUG              = False
VERBOSE            = False
VXLAN_UDP_PORT     = 4789
errors             = 0

VLAN_XLATE_TBL     = []
EGR_VLAN_XLATE_TBL = []
MPLS_ENTRY_TBL     = []
L2_ENTRY_TBL       = []
VFI_L2_ENTRY_TBL   = {}
tunnel_dvps        = {}
port_tab           = {} # dictionary of {swp: xe}
vlan_tab           = {} # dictionary of {port: vlan} for vlan devices
local_macs         = {} # dictionary of {bridge: {mac: dst if}}
remote_macs        = {} # dictionary of {vxlan: {mac: dst ip}}

def debug_print(line):
    if DEBUG:
        print line

def verbose_print(line):
    if VERBOSE:
        print '\t\t\t\t' + line

def verbose_print_fields(d, fields):
    if VERBOSE:
        for f in fields:
            print '\t\t\t\t\t%s: %s' % (f, d[f])

def error_print(line):
    global errors
    print 'ERR: ' + line
    errors = errors + 1

def get_cmd_output(cmds):
    p = subprocess.Popen(cmds.split(), stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    (stdout, stderr) = p.communicate()
    return stdout.splitlines()

# dictionary of {swp: xe}
def get_port_tab():
    with open(PORTTAB, 'r') as f:
        port_defs = f.readlines()
        for l in port_defs:
            if l.find('swp') <> -1:
                k = l.split('\t')
                port_tab[k[0]] = k[1]

# dictionary of {port: vlan} for vlan devices
def get_port_and_vlans():
    try:
        with open(VLAN_CFG, 'r') as f:
            vlans = f.readlines()
            for l in range(2, len(vlans)):
                lv = vlans[l].split('|')
                vlan_tab[lv[0].strip()] = (lv[2].strip(), lv[1].strip())
    except Exception, e:
        pass

# dictionary of {bridge: {mac: dst if}}
def get_local_macs(bridge):
    lines = get_cmd_output('brctl showmacs %s' % bridge)
    for l in lines:
        if l.find('ageing') <> -1:
            continue
        f = l.split()
        if f[2] == 'no':
            m = ''.join(f[1].split(':'))
            if not local_macs.get(bridge):
                local_macs[bridge] = {}
            local_macs[bridge][f[1]] = f[0]

# dictionary of {vxlan: {mac: dst ip}}
def get_remote_macs():
    lines = get_cmd_output('bridge fdb show')
    for l in lines:
        if l.find('dst') == -1:
            continue
        f = l.split()
        m = ''.join(f[0].split(':'))
        if not f[2] in remote_macs.keys():
            remote_macs[f[2]] = {}
        remote_macs[f[2]][f[0]] = f[4]   # dst ip

# returns a decimal number e.g. 49 from 'xe49'
def get_bcm_port(swp_name):
    bcm_port = port_tab[swp_name]
    if bcm_port.find('xe') <> -1:
        return int(bcm_port[2:], 10) + 1
    error_print('cannot find bcm port for %s' % swp_name)
    return None

def get_bcm_fields(entry):
    dict = {}
    fields = entry[entry.find(':')+2:].strip('<').strip().rstrip('>').split(',')
    for k in fields:
        p = k.split('=')
        if len(p) > 1:
            p[0] = p[0].lstrip('\n').lstrip()
            dict[p[0]] = p[1]
    return dict

def verbose_print_entry_index(e):
    verbose_print(e.split(':')[0])

def get_bcm_single_entry(table, index):
    cmd = BCMCMD + ' dump {0} {1}'.format(table, index)
    lines = get_cmd_output(cmd)
    verbose_print_entry_index(lines[0])
    return get_bcm_fields(lines[0])

def get_bcm_table(table_name):
    tbl = []
    lines = get_cmd_output(BCMCMD + ' dump ' + table_name)
    for l in lines:
        d = get_bcm_fields(l)
        tbl.append((d, l))
    return tbl

def get_local_if_info(iface_name):
    if iface_name in vlan_tab.keys():
        p, v = vlan_tab.get(iface_name)
        bcm_port = get_bcm_port(p)
        if bcm_port == None:
            error_print('cannot find bcm port for %s' %p)
            return None, 0, None

        vlan = int(v, 10)
        # get vlan_xlate
        for e in VLAN_XLATE_TBL:
            d = e[0]
            if d['KEY_TYPE'] == '4' and \
               d['SVP_VALID'] == '1' and \
               int(d['PORT_NUM'], 16) == bcm_port and \
               int(d['OVID'], 16) == vlan:
                verbose_print_entry_index(e[1])
                verbose_print_fields(d, ('KEY_TYPE', 'SVP_VALID', 'SOURCE_VP', 'PORT_NUM', 'OVID'))
                return int(d['SOURCE_VP'], 16), bcm_port, vlan
        error_print('cannot find valid vlan_xlate entry for %s!' % iface_name)
    else:
        # single entry
        bcm_port = get_bcm_port(iface_name)
        if bcm_port == None:
            error_print('cannot find bcm port for %s' %iface_name)
            return None, 0, None

        d = get_bcm_single_entry('source_trunk_map', (bcm_port + 128))
        verbose_print_fields(d, ('SVP_VALID', 'SOURCE_VP'))
        if d['SVP_VALID'] == '1':
            return int(d['SOURCE_VP'], 16), bcm_port, None
        error_print('cannot find valid source_trunk_map entry for %s!' % iface_name)
    return None, 0, None

def get_vfi_from_source_vp(svp):
    d = get_bcm_single_entry('source_vp', svp)
    if d['ENTRY_TYPE'] == '1':
        verbose_print_fields(d, ('ENTRY_TYPE', 'VFI', 'CML_FLAGS_NEW', 'CML_FLAGS_MOVE'))
        return int(d['VFI'], 16)

def get_vfi_from_vnid(vnid):
    for e in EGR_VLAN_XLATE_TBL:
        d = e[0]
        if d['ENTRY_TYPE'] == '8' and d['VALID'] == '1':
            vni = int(d['VXLAN_VFI:VN_ID'], 16)
            if vni == vnid:
                vfi = int(d['VXLAN_VFI:VFI'], 16)
                debug_print('  vfi: {0}'.format(vfi))
                verbose_print_entry_index(e[1])
                verbose_print_fields(d, ('VALID', 'ENTRY_TYPE', 'VXLAN_VFI:VFI', 'VXLAN_VFI:VN_ID'))
                return vfi
    error_print('cannot find vfi for vnid {0}'.format(vnid))
    return None

def get_vfi_from_tun_term(vnid):
    for e in MPLS_ENTRY_TBL:
        d = e[0]
        if d['KEY_TYPE'] == '9' and d['VALID'] == '1':
            vfi = int(d['VXLAN_VN_ID:VN_ID'], 16)
            if vfi == vnid:
                verbose_print_entry_index(e[1])
                verbose_print_fields(d, ('VALID', 'KEY_TYPE', 'VXLAN_VN_ID:VN_ID'))
                return int(d['VXLAN_VN_ID:VFI'], 16)
    error_print('cannot find vfi from tunnel terminator')
    return None
    
def get_bc_index_from_vfi(vfi):
    d = get_bcm_single_entry('vfi', vfi)
    verbose_print_fields(d, ('BC_INDEX', 'L2_PROTOCOL_TO_CPU'))
    if d['BC_INDEX'] <> '0':
        if d['L2_PROTOCOL_TO_CPU'] <> '1':
            error_print('L2_PROTOCOL_TO_CPU: incorrect')
            return None
        return int(d['BC_INDEX'], 16)


"""
    validate local macs:
    - verify correct vfi and hw mac entry type
    - ensure kernel and hw are in sync about local macs in the
      particular vfi/vxlan instance; ensure output interface
      consistent
    - TBD: currently not checking for macs in hw but not in kernel
"""
def validate_local_macs(br_name, vfi, local_ports):
    debug_print('\n  local macs:')

    k_macs = local_macs.get(br_name)
    if k_macs == None:
        debug_print('\tNo Local MAC on vfi {0}'.format(vfi))
        return

    if not VFI_L2_ENTRY_TBL.has_key(vfi):
        debug_print('\tNo Local MAC on vfi {0}'.format(vfi))
        return  

    for e in VFI_L2_ENTRY_TBL[vfi]:
        d = e[0]
        if d['DEST_TYPE'] <> '2' or int(d['L2:VFI'], 16) <> vfi:
            continue

        m = d['L2:MAC_ADDR'][2:].zfill(12)
        mac = ':'.join(m[i:i+2] for i in range(0, 12, 2))
        if mac in k_macs.keys():
            if k_macs[mac] <> local_ports[int(d['DESTINATION'], 16)][0]:
                error_print('mac: %s, output port mismatch!: %s vs %s' %(d['L2:MAC_ADDR'], \
                            d['DESTINATION'], k_macs[mac]))
                continue
            debug_print('\t<%s: vp = %s>' % (mac, d['DESTINATION']))
            verbose_print_entry_index(e[1])
            verbose_print_fields(d, ('DEST_TYPE', 'L2:VFI', 'L2:MAC_ADDR', 'DESTINATION'))
            del k_macs[mac]

    if len(k_macs.keys()) <> 0:
        for m in k_macs.keys():
            error_print('mac %s on %s exists in kernel but not in hw' % (m, br_name))

# this returns the set of tunnel next hops and egress ports
def validate_tunnel_vp(vp, dest_ip):
    global tunnel_dvps
    nhs = []
    eports = []
    debug_print('\t<vp: {0}>'.format(vp))


    # verify the tunnel termination for this dest
    debug_print('\t\tterminator:')
    found = False
    for e in MPLS_ENTRY_TBL:
        d = e[0]
        if d['VALID'] == '1' and d['KEY_TYPE'] == '8':
            svp = d['VXLAN_SIP:SVP']
            sip = d['VXLAN_SIP:SIP'][2:].zfill(8)
            s_str = '.'.join(str(int(sip[i:i+2], 16)) for i in range(0, 8, 2))
            if svp == vp and s_str == dest_ip:
                verbose_print_entry_index(e[1])
                verbose_print_fields(d, ('VALID', 'KEY_TYPE', 'VXLAN_SIP:SVP', 'VXLAN_SIP:SIP'))
                vfi = get_vfi_from_source_vp(svp)
                found = True
                break
    if not found:
        error_print('tunnel termination for dest %s is incorrect!' % dest_ip)
        return None, None
 

    if vp in tunnel_dvps.keys():
        if tunnel_dvps[vp][0] <> dest_ip:
            error_print('dst ip {0} mismatch (should be {1})!'.format(dest_ip, tunnel_dvps[vp][0]))
            return None, None
        return tunnel_dvps[vp][1], tunnel_dvps[vp][2]

    # get the egr_dvp_attribute, this gives tunnel index and dip
    debug_print('\t\tinitiator:')
    debug_print('\t\t\t<dip: %s' % dest_ip)
    d = get_bcm_single_entry('egr_dvp_attribute', vp)

    tindex = d['VXLAN:TUNNEL_INDEX']
    dip = d['VXLAN:DIP'][2:].zfill(8)

    verbose_print_fields(d, ('VXLAN:DVP_IS_NETWORK_PORT', 'VP_TYPE', 'VXLAN:TUNNEL_INDEX'))
    if d['VXLAN:DVP_IS_NETWORK_PORT'] <> '1' or d['VP_TYPE'] <> '2':
        error_print('egr_dvp_attribute {0} type {1},{2} mismatch!'.format(vp, d['VXLAN:DVP_IS_NETWORK_PORT'], d['VP_TYPE']))
    t_str = '.'.join(str(int(dip[i:i+2], 16)) for i in range(0, 8, 2))
    if t_str <> dest_ip:
        error_print('dst ip {0} mismatch (should be {1})!'.format(t_str, dest_ip))
        return None, None

    # verify the tunnel encap info
    d = get_bcm_single_entry('egr_ip_tunnel', tindex)
    verbose_print_fields(d, ('TUNNEL_TYPE', 'SIP', 'L4_DEST_PORT'))
    if d['TUNNEL_TYPE'] <> '0xb':
        error_print('tunnel type {0} mismatch (0xb)!'.format(d['TUNNEL_TYPE']))
        return None, None
    # check the tunnel source ip and L4 dst port
    if int(d['L4_DEST_PORT'], 16) <> VXLAN_UDP_PORT:
        error_print('vxlan udp port {0} incorrect!'.format(d['L4_DEST_PORT']))
        return None, None
    debug_print('\t\t\t dip: {0}, tindex = {1}>\n'.format(dest_ip, tindex))


    d = get_bcm_single_entry('ing_dvp_table', vp)
    verbose_print_fields(d, ('NETWORK_PORT', 'VP_TYPE', 'ECMP', 'NEXT_HOP_INDEX', 'ECMP_PTR'))
    if d['NETWORK_PORT'] <> '1' or d['VP_TYPE'] <> '3':
        error_print('tunnel dvp {0} type {1},{2} mismatch!'.format(vp, d['NETWORK_PORT'], d['VP_TYPE']))
        return None, None
    if d['ECMP'] == '0':
        nhs.append(d['NEXT_HOP_INDEX'])
    else:
        ecmp = d['ECMP_PTR']
        e = get_bcm_single_entry('l3_ecmp_group', ecmp)
        verbose_print_fields(e, ('BASE_PTR', 'COUNT'))
        base = e['BASE_PTR']
        if e['BASE_PTR'].find('0x') <> -1:
            base = e['BASE_PTR'][2:]
        debug_print('\t\t\t<ecmp group: {0}, base {1}, count {2}>'.format(ecmp, e['BASE_PTR'], e['COUNT']))
        for i in range(0, int(e['COUNT'], 10)):
            nhi = int(base, 16) + i
            el = get_bcm_single_entry('l3_ecmp', nhi)
            nhs.append(el['NEXT_HOP_INDEX'])
            verbose_print_fields(el, ['NEXT_HOP_INDEX'])
   
    # verify each next hop
    for nhi in nhs:
        port = get_ucast_nh_entry(nhi)
        if port <> None:
            eports.append(port)
        
    tunnel_dvps[vp] = (dest_ip, nhs, eports)

    return nhs, eports
    
def get_ucast_nh_entry(nhi):
    # ing_l3_next_hop
    #
    debug_print('\t\t\t<nhi {0}:'.format(nhi))
    d = get_bcm_single_entry('ing_l3_next_hop', nhi)
    if d['ENTRY_TYPE'] <> '2':
        error_print('next hop {0} type mismatch!'.format(nhi))
        return None
    if d['PORT_NUM'].find('0x') <> -1:
        port = int(d['PORT_NUM'][2:], 16)
    else:
        port = int(d['PORT_NUM'], 16)
    verbose_print_fields(d, ('ENTRY_TYPE', 'PORT_NUM'))

    # egr_port_to_nhi_mapping
    #
    lines = get_cmd_output(BCMCMD + ' getreg egr_port_to_nhi_mapping.xe%d' % (port - 1))
    d = get_bcm_fields(lines[1])

    #if d['NEXT_HOP_INDEX'] <> nhi:
    #    error_print('nhi = %s, egr_port_to_ngi_mapping.xe%d (%s) incorrect!' \
    #                % (nhi, port - 1, d['NEXT_HOP_INDEX']))
    #    return
    # TBD: we cannot assume ing_l3_next_hop nhi is same as egr_l3_next_hop nhi
    # because on egress, we could have allocated nhi for mcast egress which is
    # not needed on the ingress.  What we really need to verify is egress mac,
    # vlan, and l3_intf are consistent with the routing next hop info
    #
    verbose_print(lines[0].split('[')[0])
    verbose_print_fields(d, ['NEXT_HOP_INDEX'])


    # egr_l3_next_hop
    #
    d = get_bcm_single_entry('egr_l3_next_hop', nhi)
    if d['ENTRY_TYPE'] <> '0' or d['L3:DVP_VALID'] <> '0':
        error_print('egr_l3_next_hop {0} type or dvp valid setting incorrect!'.format(nhi))
        return None
    macda = d['L3:MAC_ADDRESS'][2:]
    l3if = d['INTF_NUM']
    verbose_print_fields(d, ('ENTRY_TYPE', 'L3:DVP_VALID', 'L3:MAC_ADDRESS', 'INTF_NUM'))

    # egr_l3_intf
    #
    d = get_bcm_single_entry('egr_l3_intf', l3if)
    verbose_print_fields(d, ('MAC_ADDRESS', 'VID'))
    macsa = d['MAC_ADDRESS'][2:]
    int_vlan = int(d['VID'], 16)
    debug_print('\t\t\t nhi {0}: port {1}, mac-da {2} mac-sa {3} int-vlan {4}>'.\
                format(nhi, port, macda, macsa, int_vlan))
    return port

def get_mcast_nh_entry(nhi):
    debug_print('\t\t<nhi: {0}'.format(nhi))
    d = get_bcm_single_entry('egr_l3_next_hop', nhi)
    if 'ENTRY_TYPE' in d.keys() and d['ENTRY_TYPE'] == '7':  # mc network view
        if d['L3MC:DVP_VALID'] <> '1':
            error_print('egr_l3_next_hop {0} dvp_valid setting incorrect!'.format(nhi))
            return
        macda = d['L3MC:MAC_ADDRESS'][2:]
        l3if = d['L3MC:INTF_NUM']
        dvp = d['L3MC:DVP']
        verbose_print_fields(d, ('ENTRY_TYPE', 'L3MC:DVP_VALID', 'L3MC:MAC_ADDRESS', 'L3MC:INTF_NUM', 'L3MC:DVP'))
        d = get_bcm_single_entry('egr_dvp_attribute', dvp)
        if d['VP_TYPE'] <> '2' or d['VXLAN:DVP_IS_NETWORK_PORT'] <> '1':
            error_print('egr_dvp_attribute {0} vp or network_port setting mismatch!'.format(nhi))
            return
        dip = d['VXLAN:DIP']
        tindex = d['VXLAN:TUNNEL_INDEX']
        verbose_print_fields(d, ('VP_TYPE', 'VXLAN:DVP_IS_NETWORK_PORT', 'VXLAN:DIP', 'VXLAN:TUNNEL_INDEX'))

        d = get_bcm_single_entry('egr_l3_intf', l3if)
        macsa = d['MAC_ADDRESS'][2:]
        int_vlan = int(d['VID'], 16)
        verbose_print_fields(d, ('MAC_ADDRESS', 'VID'))
        output = '\t\t nhi: {0}, mac-da {1} mac-sa {2} int-vlan {3}>'.format(nhi, macda, macsa, int_vlan)
    elif d['ENTRY_TYPE'] == '2': # sdtag view for local
        if d['SD_TAG:DVP_IS_NETWORK_PORT'] <> '0':
            error_print('dvp {0} should not be network port!'.format(nhi))
            return

        dvp = d['SD_TAG:DVP'] # use it to match the local port's vp

        if d['SD_TAG:SD_TAG_ACTION_IF_PRESENT'] == '2' and \
           d['SD_TAG:SD_TAG_ACTION_IF_NOT_PRESENT'] == '1':
            vlan = d['SD_TAG:SD_TAG_VID']
            output = ' vlan = {0}'.format(vlan)
        elif d['SD_TAG:SD_TAG_ACTION_IF_PRESENT'] == '3' and \
             d['SD_TAG:SD_TAG_ACTION_IF_NOT_PRESENT'] == '0':
            int_vlan = d['SD_TAG:SD_TAG_VID']
            output = '\t\t nhi: {0} int-vlan = {1}>'.format(nhi, int_vlan)

        verbose_print_fields(d, ('ENTRY_TYPE', 'SD_TAG:DVP_IS_NETWORK_PORT', 'SD_TAG:DVP', 'SD_TAG:SD_TAG_ACTION_IF_PRESENT', 'SD_TAG:SD_TAG_ACTION_IF_NOT_PRESENT', 'SD_TAG:SD_TAG_VID'))

    debug_print(output)


def validate_remote_macs(vx_name, vfi):
    dvps   = {}
    nhi    = Set()
    ep     = Set()

    debug_print('\n  remote macs:')
    k_macs = remote_macs.get(vx_name)

    if k_macs == None:
        debug_print('\tNo Remote MAC on vfi {0}'.format(vfi))
        return (None, None)

    if not VFI_L2_ENTRY_TBL.has_key(vfi):
        debug_print('\tNo Remote MAC on vfi {0}'.format(vfi))
        return (None, None)

    for e in VFI_L2_ENTRY_TBL[vfi]:
        d = e[0]
        if d['DEST_TYPE'] <> '2' or int(d['L2:VFI'], 16) <> vfi:
            continue

        m = d['L2:MAC_ADDR'][2:].zfill(12)
        mac = ':'.join(m[i:i+2] for i in range(0, 12, 2))
        if mac in k_macs.keys():
            vp = d['DESTINATION']
            debug_print('\t<{0}: dst ip = {1}, vp = {2}>'.format(mac, k_macs[mac], vp))
            verbose_print_entry_index(e[1])
            verbose_print_fields(d, ('DEST_TYPE', 'L2:VFI', 'L2:MAC_ADDR', 'DESTINATION'))
            dvps[vp] = k_macs[mac]
            del k_macs[mac]

    if len(k_macs.keys()) <> 0:
        for m in k_macs.keys():
            error_print('mac {0} on {1} exists in kernel but not in hw'.format( m, vx_name))

    debug_print('\n  tunnel vp:')
    for p in dvps.keys():
        nhs, eps = validate_tunnel_vp(p, dvps[p])
        if nhs <> None:
            nhi = nhi | Set(nhs)
        if eps <> None:
            ep = ep | Set(eps)
    return nhi, ep

def get_port_info_from_dvp(vp, subint):
    d = get_bcm_single_entry('ing_dvp_table', vp)
    if d['NETWORK_PORT'] <> '0' or d['ECMP'] <> '0' or d['VP_TYPE'] <> '0':
        return None, None, None
    verbose_print_fields(d, ('NETWORK_PORT', 'ECMP', 'VP_TYPE', 'NEXT_HOP_INDEX'))

    nh = int(d['NEXT_HOP_INDEX'], 16)
    d = get_bcm_single_entry('ing_l3_next_hop', nh)
    if d['ENTRY_TYPE'] <> '0' or d['DROP'] <> '0':
        return None, None, None

    verbose_print_fields(d, ('ENTRY_TYPE', 'DROP', 'PORT_NUM'))

    #int_vlan = d['VLAN_ID']
    bcm_port = int(d['PORT_NUM'], 16)
    d = get_bcm_single_entry('egr_l3_next_hop', nh)
    if d['ENTRY_TYPE'] <> '2':
        return None, None, None

    verbose_print_fields(d, ('ENTRY_TYPE', 'SD_TAG:SD_TAG_ACTION_IF_PRESENT', 'SD_TAG:SD_TAG_ACTION_IF_NOT_PRESENT', 'SD_TAG:SD_TAG_VID'))
    if subint:
        if d['SD_TAG:SD_TAG_ACTION_IF_PRESENT'] <> '2' or \
            d['SD_TAG:SD_TAG_ACTION_IF_NOT_PRESENT'] <> '1':
            error_print('Invalid tag action: IF_PRESENT {0}, IF_NOT_PRESENT {1}'. \
                        format(d['SD_TAG:SD_TAG_ACTION_IF_PRESENT'], \
                               d['SD_TAG:SD_TAG_ACTION_IF_NOT_PRESENT']))
            return None, None, None
        vlan = int(d['SD_TAG:SD_TAG_VID'], 16)
    else:
        if d['SD_TAG:SD_TAG_ACTION_IF_PRESENT'] <> '3' or \
            d['SD_TAG:SD_TAG_ACTION_IF_NOT_PRESENT'] <> '0':
            error_print('Invalid tag action: IF_PRESENT {0}, IF_NOT_PRESENT {1}'. \
                        format(d['SD_TAG:SD_TAG_ACTION_IF_PRESENT'], \
                               d['SD_TAG:SD_TAG_ACTION_IF_NOT_PRESENT']))
            return None, None, None
        vlan = None
    return bcm_port, vlan, nh

def validate_one_local_port(iface_name, vx_vfi):
    debug_print('\t<%s: ' % iface_name)
    vp, bcm_port, vlan = get_local_if_info(iface_name)
    if vp == None or bcm_port == 0:
        return '', bcm_port 
    output = '\t {0}: vp = {1}'.format(iface_name, vp)

    vfi = get_vfi_from_source_vp(vp)
    if vfi == 0 or vfi != vx_vfi:
        error_print('Invalid vfi {0}!'.format(vfi))
        return '', None

    p, v, nh = get_port_info_from_dvp(vp, (vlan <> None))
    if p:
        output = output + ', port = {0}'.format(p)
        if p != bcm_port:
            error_print('port {0} mismatch with bcm port {1}!'.format(p, bcm_port))
            return '', None
    if v:
        output = output + ', vlan = {0}'.format(v)
        if v <> vlan:
            error_print('vlan mismatch! {0} {1}'.format(v, vlan))
            return '', None
    if nh:
        output = output + ', nhi = {0}'.format(nh)

    debug_print(output + '>\n')
    return vp, p


def get_and_validate_mcast_group(vfi, local_ports, output_ports):
    debug_print('\n  mcast group:')
    bc_index = get_bc_index_from_vfi(vfi)
    if bc_index == 0:
        error_print('Invalid bc_index 0 for vxlan %s!' % vx_name)
        return
    debug_print('\n\t<mcast group: {0}'.format(bc_index))

    d = get_bcm_single_entry('l3_ipmc', bc_index)
    if d['VALID'] <> '1':
        error_print('Invalid mcast entry {0} for vxlan {1}!'.format(bc_index, vx_name))
        return
    verbose_print_fields(d, ('VALID', 'L3_BITMAP'))
    
    l3bmp = d['L3_BITMAP']
    l3bmp_hex = int(l3bmp, 16)
    bmp = 0
    for lp in local_ports.keys():
        bmp |= 1 << local_ports[lp][1]

    for ep in output_ports:
        bmp |= 1 << ep

    # validate the member bitmap.  If service node is used, the hw bitmap
    # maybe a subset of the sw bitmap, but all local ports and at least
    # one remote endpoint should be part of it, except in the case when
    # there is no remote mac associated with the service node tunnel
    if (l3bmp_hex & bmp) != l3bmp_hex:
        error_print('L3 bitmap sw:{0} mismatch hw:({1})!'.format(hex(bmp), l3bmp))
        #return

    # the pipe member bmp records the logical port of the pipe, not the
    # normal bcm port
    mc_nhi = []
    d = get_bcm_single_entry('mmu_repl_group_info0', bc_index)
    verbose_print_fields(d, ('PIPE_BASE_PTR', 'PIPE_MEMBER_BMP'))
    pipex_base = int(d['PIPE_BASE_PTR'], 16)
    mbr_bmp = int(d['PIPE_MEMBER_BMP'], 16)
    mbr = 0
    while mbr_bmp <> 0:
        if (mbr_bmp & 1) == 1:
            head = pipex_base + mbr
            mbr = mbr + 1
            d = get_bcm_single_entry('mmu_repl_head_tbl', head)
            head_ptr = int(d['HEAD_PTR'], 16)
            verbose_print_fields(d, ['HEAD_PTR'])
            d = get_bcm_single_entry('mmu_repl_list_tbl', head_ptr)
            next_ptr = int(d['NEXTPTR'], 16)
            while True:
                # get the nexthop index
                if d['MODE'] == '0':
                    lsb = int(d['LSB_VLAN_BM'], 16)
                    msb = int(d['MSB_VLAN'], 16) * 64
                    verbose_print_fields(d, ('NEXTPTR', 'MODE', 'LSB_VLAN_BM', 'MSB_VLAN'))
                    for i in range(0, 64):
                        if ((1 << i) & lsb) <> 0:
                            mc_nhi.append(msb + i)
                else:
                    mode1bmp = int(d['MODE_1_BITMAP'], 16)
                    verbose_print_fields(d, ('NEXTPTR', 'MODE', 'MODE_1_BITMAP'))
                    for i in range(0, 4):
                        if ((1 << i) & mode1bmp) <> 0:
                            nh_str = 'NEXT_HOP_INDEX_%d' % i
                            mc_nhi.append(d[nh_str])
                    
                if next_ptr == head_ptr:
                    break
        mbr_bmp = mbr_bmp >> 1

    for mc in mc_nhi:
        get_mcast_nh_entry(mc)
 

def validate_vfi(vx_name, vnid):
    v_vfi = get_vfi_from_vnid(vnid)
    t_vfi = get_vfi_from_tun_term(vnid)

    if t_vfi != v_vfi:
        error_print('vxlan <{0}>: vfi mismatch: n2h {1}, h2n {2}'.format(vx_name, t_vfi, v_vfi))
    return v_vfi
   

def validate_local_ports(vfi, br_name, vx_name):
    local_ports = {}
    debug_print('  local interfaces:')
    brif_path = BRIDGE_ROOT + br_name + '/brif'
    brifs = get_cmd_output('ls %s' % brif_path)
    for n in brifs:
        if n == vx_name:
            continue
        vp, p = validate_one_local_port(n, vfi)
        if vp <> None:
            local_ports[vp] = (n, p)
    return local_ports


def validate_vxlan_instance(vx_name, vnid, br_name):
    local_ports = {}  # hash key is vp, data is (port name, port number)

    debug_print('\n<vxlan: %s> - <vnid: %s> - <bridge: %s>' % (vx_name, vnid, br_name))
    debug_print('------------------------------------------------------------------------------')

    # get vfi, check consistency between tunnel initiation and termination
    vfi = validate_vfi(vx_name, vnid)

    # validate local ports, including ingress svp mapping and egress dvp mapping
    # as well as sd tag actions
    local_ports = validate_local_ports(vfi, br_name, vx_name)

    # validate macs and tunnels
    validate_local_macs(br_name, vfi, local_ports)
    nhi, network_ports = validate_remote_macs(vx_name, vfi)

    # validate mcast group
    if not (nhi == None or network_ports == None):
        get_and_validate_mcast_group(vfi, local_ports, network_ports)

           
def setup_arg_parser():
    optcfg = optparse.OptionParser(usage="usage: cl-nsx-check [-d] [-v]")
    optcfg.add_option("-d", dest="DEBUG", action="store_true", default=False,
                      help="enable debug output")
    optcfg.add_option("-v", dest="VERBOSE", action="store_true", default=False,
                      help="enable verbose output which includes hardware entry info")
    optcfg.add_option("-m", dest="mac", action="store",
                      help="track the setting of a mac for a vxlan instance")
    optcfg.add_option("-x", dest="vxlan", action="store",
                      help="track the setting of a mac for a vxlan instance")
    (opts, args) = optcfg.parse_args()
    return opts, args


def validate_one_mac(mac, vxlan, vnid, bridge):
    local = False
    found = False

    print 'validate mac:{0} vxlan:{1}'.format(mac, vxlan)

    if remote_macs.get(vxlan):
        if remote_macs[vxlan].get(mac):
            dst = remote_macs[vxlan][mac]
            found = True
    if not found and local_macs.get(bridge):
        if local_macs[bridge].get(mac):
            dst = local_macs[bridge][mac]
            local = True
            found = True
    if not found:
        print 'cannot find mac on vxlan'
        return False
 
    vfi = get_vfi_from_vnid(vnid)
    for e in VFI_L2_ENTRY_TBL[vfi]:
        d = e[0]
        if d['DEST_TYPE'] <> '2' or int(d['L2:VFI'], 16) <> vfi:
            continue

        one_mac = d['L2:MAC_ADDR'][2:].zfill(12)
        if one_mac <> mac.replace(':',''):
            continue

        verbose_print_entry_index(e[1])
        verbose_print_fields(d, ('DEST_TYPE', 'L2:VFI', 'L2:MAC_ADDR', 'DESTINATION'))
        if local:
            validate_one_local_port(dst, vfi)
        else:
            validate_tunnel_vp(d['DESTINATION'], dst)
        return True

    return False


def main(args):
    global VLAN_XLATE_TBL
    global EGR_VLAN_XLATE_TBL
    global MPLS_ENTRY_TBL
    global L2_ENTRY_TBL
    global tunnel_dvps
    global port_tab
    global vlan_tab
    global local_macs
    global remote_macs
    global DEBUG
    global VERBOSE
 
    opts, args = setup_arg_parser()
    DEBUG = opts.DEBUG
    VERBOSE = opts.VERBOSE

    if opts.mac and not opts.vxlan:
        print 'require vxlan name'
        return

    # get the porttab for swp to xe mapping and vlan devices
    get_port_tab()
    get_port_and_vlans()
    get_remote_macs()

    # get the tables that we don't have an entry index off hand
    VLAN_XLATE_TBL = get_bcm_table('vlan_xlate')
    EGR_VLAN_XLATE_TBL = get_bcm_table('egr_vlan_xlate')
    MPLS_ENTRY_TBL = get_bcm_table('mpls_entry')
    L2_ENTRY_TBL = get_bcm_table('l2_entry')

    # extract the vxlan macs (local and remote) from l2 table
    for e in L2_ENTRY_TBL:
        d = e[0]
        if d['DEST_TYPE'] <> '2':
            continue
        vfi = int(d['L2:VFI'], 16)
        if vfi not in VFI_L2_ENTRY_TBL.keys():
            VFI_L2_ENTRY_TBL[vfi] = []
        VFI_L2_ENTRY_TBL[vfi].append(e)

    # look at the vxlan device
    lines = get_cmd_output('ip -d link show')
    for l in lines:
        if l.find('vxlan id') == -1:
            continue

        link = lines[lines.index(l) - 2]
        if link.find('master') == -1:
            continue

        f1 = link.split()
        vxlan = f1[1].strip(':')
        bridge = f1[8]
        vnid = int(l.split()[2], 10)

        if opts.vxlan and opts.vxlan != vxlan:
            continue

        get_local_macs(bridge)
        if opts.mac:
            validate_one_mac(opts.mac, opts.vxlan, vnid, bridge)
            break
        else:
            validate_vxlan_instance(vxlan, vnid, bridge)
            if opts.vxlan:
                break

    print '\n\nErrors: %d' % errors


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
