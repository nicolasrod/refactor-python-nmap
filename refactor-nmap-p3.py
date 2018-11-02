#!/usr/bin/env python
# -*- coding: utf-8 -*-

import csv
import io
import os
import re
import shlex
import subprocess
import sys

from functools import wraps, partialmethod
from xml.etree import ElementTree as ET
from multiprocessing import Process
from collections import defaultdict

__author__ = 'Alexandre Norman (norman@xael.org)'
__version__ = '0.6.3'
__last_modification__ = '2018/09/23'

_DEFAULT_SEARCHPATH = ('nmap', '/usr/bin/nmap', '/usr/local/bin/nmap', '/sw/bin/nmap', '/opt/local/bin/nmap')

def when_scan_done(f):
    @wraps(f)
    def wrapper(*args, **kwarg):
        assert 'nmap' in args[0]._scan_result and 'scan' in args[0]._scan_result, \
            'Do a scan before trying to get result !'
        return f(*args)
    return wrapper

def _expr(f, def_, *args, **kwargs):
    try:
        return f(*args, **kwargs)
    except:
        return def_


class PortScanner(object):
    def __init__(self, nmap_search_path=_DEFAULT_SEARCHPATH):
        self._nmap_path = ''  # nmap path
        self._scan_result = defaultdict(dict)
        self._nmap_version = None  # nmap version number
        self._nmap_last_output = ''  # last full ascii nmap output
       
        regex = re.compile('Nmap version ([0-9]*)\.([0-9]*)[^ ]* \( http(|s)://.* \)')
        kwargs = dict(bufsize=10000, stdout=subprocess.PIPE)

        if sys.platform.startswith('freebsd') or \
                sys.platform.startswith('linux') or \
                sys.platform.startswith('darwin'):
            kwargs['close_fds'] = True

        for nmap_path in nmap_search_path:
            try:
                p = subprocess.Popen([nmap_path, '-V'], **kwargs)
                self._nmap_path = nmap_path
                break
            except OSError:
                pass
        else:
            raise RuntimeError('nmap program was not found in path. PATH is : {0}'.format(os.getenv('PATH')))

        self._nmap_last_output = bytes.decode(p.communicate()[0])
        m = regex.match(self._nmap_last_output)
        if m is not None:
            self._nmap_version = (int(m.group(1)),int(m.group(2)))
        else:
            raise RuntimeError('nmap program was not found in path')

    def get_nmap_last_output(self):
        return self._nmap_last_output

    def nmap_version(self):
        return self._nmap_version

    def listscan(self, hosts='127.0.0.1'):
        assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))

        output = self.scan(hosts, arguments='-sL')
        err = _expr(lambda : output['nmap']['scaninfo']['error'][0], '')
        if 'looks like an IPv6 target specification' in err:
            self.scan(hosts, arguments='-sL -6')
        return self.all_hosts()

    def scan(self, hosts='127.0.0.1', ports=None, arguments='-sV', sudo=False):
        assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
        assert type(ports) in (str, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(
            type(ports))
        assert type(arguments) is str, 'Wrong type for [arguments], should be a string [was {0}]'.format(
            type(arguments))

        for arg in ['-oX', '-oA']:
            assert arg not in arguments, 'Xml output can\'t be redirected from command line.\nYou can access it after a scan using:\nnmap.nm.get_nmap_last_output()'

        h_args = shlex.split(hosts)
        f_args = shlex.split(arguments)

        args = [self._nmap_path, '-oX', '-'] + h_args + ['-p', ports] * (ports is not None) + f_args
        if sudo:
            args = ['sudo'] + args

        p = subprocess.Popen(args, bufsize=100000, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

        _out, _err = p.communicate()
        self._nmap_last_output = bytes.decode(_out)
        nmap_err = bytes.decode(_err)

        err_trace = []
        warn_trace = []
        if len(nmap_err) > 0:
            regex_warning = re.compile('^Warning: .*', re.IGNORECASE)
            for line in nmap_err.split(os.linesep):
                if len(line) > 0:
                    rgw = regex_warning.search(line)
                    if rgw is not None:
                        warn_trace.append(line + os.linesep)
                    else:
                        err_trace.append(line)

        return self.analyse_nmap_xml_scan(self._nmap_last_output, nmap_err, err_trace, warn_trace)

    def analyse_nmap_xml_scan(self, nmap_xml_output=None, nmap_err='', nmap_err_keep_trace='', nmap_warn_keep_trace=''):
        if nmap_xml_output is not None:
            self._nmap_last_output = nmap_xml_output

        scan_result = defaultdict(dict)

        try:
            dom = ET.fromstring(self._nmap_last_output)
        except Exception:
            raise RuntimeError(nmap_err if len(nmap_err) > 0 else self._nmap_last_output)

        scan_result['nmap'] = dict(
            command_line=dom.get('args'),
            scaninfo=dict(
                error=nmap_err_keep_trace,
                warning=nmap_warn_keep_trace),
            scanstats=dict(
                timestr=dom.find('runstats/finished').get('timestr'),
                elapsed=dom.find('runstats/finished').get('elapsed'),
                uphosts=dom.find('runstats/hosts').get('up'),
                downhosts=dom.find('runstats/hosts').get('down'),
                totalhosts=dom.find('runstats/hosts').get('total'))
        )

        scan_result['nmap']['scaninfo'].update(
            dict([(it.get('protocol'), dict(method=it.get('type'), services=it.get('services')))
                for it in dom.findall('scaninfo')])
        )

        for dhost in dom.findall('host'):
            host = None
            address_block = {}
            vendor_block = {}
            for address in dhost.findall('address'):
                addtype = address.get('addrtype')
                address_block[addtype] = address.get('addr')
                if addtype == 'ipv4':
                    host = address_block[addtype]
                elif addtype == 'mac' and address.get('vendor') is not None:
                    vendor_block[address_block[addtype]] = address.get('vendor')

            if host is None:
                host = dhost.find('address').get('addr')

            hostnames = [dict(name='', type='')]
            node = dhost.findall('hostnames/hostname')
            if len(node) > 0:
                hostnames = [
                    dict(
                        name=it.get('name'), 
                        type=it.get('type')) 
                    for it in node
                ]

            scan_result['scan'][host] = PortScannerHostDict(
                dict(
                    hostnames=hostnames,
                    addresses=address_block,
                    vendor=vendor_block,
                    status = dict(
                        state=dhost.find('status').get('state'), 
                        reason=dhost.find('status').get('reason')),
                    uptime=dict(
                        seconds=_expr(lambda :dhost.find('uptime').get('seconds'), ''),
                        lastboot=_expr(lambda :dhost.findall('uptime').get('lastboot'), '')))
            )

            for dport in dhost.findall('ports/port'):
                dname = dport.findall('service')[-1] #@@ last item if more than 1 service tag
                
                scan_result['scan'][host][dport.get('protocol')][int(dport.get('portid'))] = \
                    dict(state=dport.find('state').get('state'), 
                        reason=dport.find('state').get('reason'),
                        name=dname.get('name'), 
                        product=dname.get('product'), 
                        version=dname.get('version'),
                        extrainfo=dname.get('extrainfo'), 
                        conf=dname.get('conf'),
                        cpe=_expr(lambda :dname.findall('cpe')[-1].text, ''), 
                        scripts=dict([(it.get('id'), it.get('output')) 
                                    for it in dport.findall('script')])
                    )

            for dhostscript in dhost.findall('hostscript'):
                scan_result['scan'][host]['hostscript'].extend([
                    dict(
                        id=it.get('id'), 
                        output=it.get('output'))
                    for it in dhostscript.findall('script')]
                )

            for dos in dhost.findall('os'):
                scan_result['scan'][host]['portused'] = [
                    dict(
                        state=it.get('state'), 
                        proto=it.get('proto'),
                        portid=it.get('portid')) 
                    for it in dos.findall('portused')
                ]

                node = dos.findall('osmatch')
                osclass = [
                    dict(
                        type=it.get('type'),
                        vendor=it.get('vendor'),
                        osfamily=it.get('osfamily'),
                        osgen=it.get('osgen'),
                        accuracy=it.get('accuracy'),
                        cpe=[x.text for x in it.findall('cpe')]) 
                    for it in dos.findall('osclass')
                ]
                
                scan_result['scan'][host]['osmatch'] = [
                    dict(
                        name=it.get('name'), 
                        accuracy=it.get('accuracy'), 
                        line=it.get('line'),
                        osclass=osclass) 
                    for it in dos.findall('osmatch')
                ]

                scan_result['scan'][host]['fingerprint'] = dos.findall('osfingerprint')[-1].get('fingerprint')

        self._scan_result = scan_result
        return scan_result

    def __getitem__(self, host):
        assert type(host) is str, 'Wrong type for [host], should be a string [was {0}]'.format(type(host))
        return self._scan_result['scan'][host]

    @when_scan_done
    def __getattr__(self, name):
        return self._scan_result['nmap'][name]

    def all_hosts(self):
        if 'scan' not in list(self._scan_result.keys()):
            return []
        listh = list(self._scan_result['scan'].keys())
        listh.sort()
        return listh

    @when_scan_done
    def has_host(self, host):
        assert type(host) is str, 'Wrong type for [host], should be a string [was {0}]'.format(type(host))

        if host in list(self._scan_result['scan'].keys()):
            return True

        return False

    @when_scan_done
    def csv(self):
        fd = io.StringIO()
        csv_ouput = csv.writer(fd, delimiter=';')
        csv_header = 'host|hostname|hostname_type|protocol|port|name|state|product|extrainfo|reason|version|conf|cpe'. \
            split('|')
        csv_ouput.writerow(csv_header)

        for host in self.all_hosts():
            for proto in self[host].all_protocols(filter_=lambda x: x in ['tcp', 'udp']):
                lport = list(self[host][proto].keys())
                lport.sort()

                for port in lport:
                    for h in self[host]['hostnames']:
                        data = self[host][proto][port]
                        csv_ouput.writerow([host, h['name'], h['type'], proto, port,
                            data['name'], data['state'], data['product'], data['extrainfo'],
                            data['reason'], data['version'], data['conf'], data['cpe']])

        return fd.getvalue()
        
    def iterscan(self, hosts='127.0.0.1', ports=None, arguments='-sV', sudo=False):
        for host in self.listscan(hosts):
            scan_data = _expr(lambda :self.scan(host, ports, arguments, sudo), None)
            yield (host, scan_data)

class PortScannerHostDict(defaultdict):
    def __init__(self, def_={}):
        super(PortScannerHostDict, self).__init__(PortScannerHostDict)
        self.update(def_)
    
    def hostname(self):
        return _expr(lambda :
            _expr(lambda :[it['name'] for it in self['hostnames'] if it['type'] == 'user'][0],
                self['hostnames'][0]['name']), '')
    
    def all_protocols(self, filter_=lambda x: x in ['ip', 'tcp', 'udp', 'sctp']):
        lp = list(filter(filter_, list(self.keys())))
        lp.sort()
        return lp

    def _all_porttype(self, type_):
        if type_ not in list(self.keys()):
            return []
        l = list(self[type_].keys())
        l.sort()
        return l

    def _has_port(self, type_, port):
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))
        return type_ in self.keys() and port in self[type_].keys()

    def _port(self, type_, port):
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))
        return self[type_][port]

    hostnames = lambda self: self['hostnames']
    state = lambda self: self['status']['state']
    uptime = lambda self: self['uptime']

    all_tcp = partialmethod(_all_porttype, 'tcp')
    has_tcp = partialmethod(_has_port, 'tcp')
    tcp = partialmethod(_port, 'tcp')

    all_udp = partialmethod(_all_porttype, 'udp')
    has_udp = partialmethod(_has_port, 'udp')
    udp = partialmethod(_port, 'udp')

    all_ip = partialmethod(_all_porttype, 'ip')
    has_ip = partialmethod(_has_port, 'ip')
    ip = partialmethod(_port, 'ip')

    all_sctp = partialmethod(_all_porttype, 'sctp')
    has_sctp = partialmethod(_has_port, 'sctp')
    sctp = partialmethod(_port, 'sctp')
