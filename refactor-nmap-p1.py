#!/usr/bin/env python
# -*- coding: utf-8 -*-

import csv
import io
import os
import re
import shlex
import subprocess
import sys
from xml.etree import ElementTree as ET

from multiprocessing import Process

__author__ = 'Alexandre Norman (norman@xael.org)'
__version__ = '0.6.3'
__last_modification__ = '2018/09/23'


_DEFAULT_SEARCHPATH = ('nmap', '/usr/bin/nmap', '/usr/local/bin/nmap', '/sw/bin/nmap', '/opt/local/bin/nmap')


class PortScanner(object):
    def __init__(self, nmap_search_path=_DEFAULT_SEARCHPATH):
        self._nmap_path = ''  # nmap path
        self._scan_result = {}
        self._nmap_version_number = 0  # nmap version number
        self._nmap_subversion_number = 0  # nmap subversion number
        self._nmap_last_output = ''  # last full ascii nmap output
        is_nmap_found = False  # true if we have found nmap

        self.__process = None

        regex = re.compile(
            'Nmap version [0-9]*\.[0-9]*[^ ]* \( http(|s)://.* \)'
        )
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
            raise PortScannerError('nmap program was not found in path. PATH is : {0}'.format(os.getenv('PATH')))

        self._nmap_last_output = bytes.decode(p.communicate()[0])  # sav stdout
        for line in self._nmap_last_output.split(os.linesep):
            if regex.match(line) is not None:
                is_nmap_found = True
                regex_version = re.compile('[0-9]+')
                regex_subversion = re.compile('\.[0-9]+')

                rv = regex_version.search(line)
                rsv = regex_subversion.search(line)

                if rv is not None and rsv is not None:
                    self._nmap_version_number = int(line[rv.start():rv.end()])
                    self._nmap_subversion_number = int(
                        line[rsv.start() + 1:rsv.end()]
                    )
                break

        if not is_nmap_found:
            raise PortScannerError('nmap program was not found in path')

        return

    def get_nmap_last_output(self):
        return self._nmap_last_output

    def nmap_version(self):
        return (self._nmap_version_number, self._nmap_subversion_number)

    def listscan(self, hosts='127.0.0.1'):
        assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))  # noqa
        output = self.scan(hosts, arguments='-sL')
        if 'scaninfo' in output['nmap'] \
                and 'error' in output['nmap']['scaninfo'] \
                and len(output['nmap']['scaninfo']['error']) > 0 \
                and 'looks like an IPv6 target specification' in output['nmap']['scaninfo']['error'][0]:  # noqa
            self.scan(hosts, arguments='-sL -6')

        return self.all_hosts()

    def scan(self, hosts='127.0.0.1', ports=None, arguments='-sV', sudo=False):
        assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))  # noqa
        assert type(ports) in (str, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(
            type(ports))  # noqa
        assert type(arguments) is str, 'Wrong type for [arguments], should be a string [was {0}]'.format(
            type(arguments))  # noqa

        for redirecting_output in ['-oX', '-oA']:
            assert redirecting_output not in arguments, 'Xml output can\'t be redirected from command line.\nYou can access it after a scan using:\nnmap.nm.get_nmap_last_output()'  # noqa

        h_args = shlex.split(hosts)
        f_args = shlex.split(arguments)

        args = [self._nmap_path, '-oX', '-'] + h_args + ['-p', ports] * (ports is not None) + f_args
        if sudo:
            args = ['sudo'] + args

        p = subprocess.Popen(args, bufsize=100000,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

        (self._nmap_last_output, nmap_err) = p.communicate()
        self._nmap_last_output = bytes.decode(self._nmap_last_output)
        nmap_err = bytes.decode(nmap_err)

        nmap_err_keep_trace = []
        nmap_warn_keep_trace = []
        if len(nmap_err) > 0:
            regex_warning = re.compile('^Warning: .*', re.IGNORECASE)
            for line in nmap_err.split(os.linesep):
                if len(line) > 0:
                    rgw = regex_warning.search(line)
                    if rgw is not None:
                        nmap_warn_keep_trace.append(line + os.linesep)
                    else:
                        nmap_err_keep_trace.append(nmap_err)

        return self.analyse_nmap_xml_scan(
            nmap_xml_output=self._nmap_last_output,
            nmap_err=nmap_err,
            nmap_err_keep_trace=nmap_err_keep_trace,
            nmap_warn_keep_trace=nmap_warn_keep_trace
        )

    def analyse_nmap_xml_scan(self, nmap_xml_output=None, nmap_err='', nmap_err_keep_trace='', nmap_warn_keep_trace=''):
        if nmap_xml_output is not None:
            self._nmap_last_output = nmap_xml_output

        scan_result = {}

        try:
            dom = ET.fromstring(self._nmap_last_output)
        except Exception:
            if len(nmap_err) > 0:
                raise PortScannerError(nmap_err)
            else:
                raise PortScannerError(self._nmap_last_output)

        scan_result['nmap'] = {
            'command_line': dom.get('args'),
            'scaninfo': {},
            'scanstats': {'timestr': dom.find("runstats/finished").get('timestr'),
                          'elapsed': dom.find("runstats/finished").get('elapsed'),
                          'uphosts': dom.find("runstats/hosts").get('up'),
                          'downhosts': dom.find("runstats/hosts").get('down'),
                          'totalhosts': dom.find("runstats/hosts").get('total')}
        }

        if len(nmap_err_keep_trace) > 0:
            scan_result['nmap']['scaninfo']['error'] = nmap_err_keep_trace

        if len(nmap_warn_keep_trace) > 0:
            scan_result['nmap']['scaninfo']['warning'] = nmap_warn_keep_trace

        for dsci in dom.findall('scaninfo'):
            scan_result['nmap']['scaninfo'][dsci.get('protocol')] = {
                'method': dsci.get('type'),
                'services': dsci.get('services')
            }

        scan_result['scan'] = {}

        for dhost in dom.findall('host'):
            # host ip, mac and other addresses
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

            hostnames = []
            if len(dhost.findall('hostnames/hostname')) > 0:
                for dhostname in dhost.findall('hostnames/hostname'):
                    hostnames.append({
                        'name': dhostname.get('name'),
                        'type': dhostname.get('type'),
                    })
            else:
                hostnames.append({
                    'name': '',
                    'type': '',
                })

            scan_result['scan'][host] = PortScannerHostDict({'hostnames': hostnames})

            scan_result['scan'][host]['addresses'] = address_block
            scan_result['scan'][host]['vendor'] = vendor_block

            for dstatus in dhost.findall('status'):
                scan_result['scan'][host]['status'] = {'state': dstatus.get('state'),
                                                       'reason': dstatus.get('reason')}
            for dstatus in dhost.findall('uptime'):
                scan_result['scan'][host]['uptime'] = {'seconds': dstatus.get('seconds'),
                                                       'lastboot': dstatus.get('lastboot')}
            for dport in dhost.findall('ports/port'):
                proto = dport.get('protocol')
                port = int(dport.get('portid'))
                state = dport.find('state').get('state')
                reason = dport.find('state').get('reason')
                name = product = version = extrainfo = conf = cpe = ''
                for dname in dport.findall('service'):
                    name = dname.get('name')
                    if dname.get('product'):
                        product = dname.get('product')
                    if dname.get('version'):
                        version = dname.get('version')
                    if dname.get('extrainfo'):
                        extrainfo = dname.get('extrainfo')
                    if dname.get('conf'):
                        conf = dname.get('conf')

                    for dcpe in dname.findall('cpe'):
                        cpe = dcpe.text
                if proto not in list(scan_result['scan'][host].keys()):
                    scan_result['scan'][host][proto] = {}

                scan_result['scan'][host][proto][port] = {'state': state,
                                                          'reason': reason,
                                                          'name': name,
                                                          'product': product,
                                                          'version': version,
                                                          'extrainfo': extrainfo,
                                                          'conf': conf,
                                                          'cpe': cpe}
                script_id = ''
                script_out = ''
                for dscript in dport.findall('script'):
                    script_id = dscript.get('id')
                    script_out = dscript.get('output')
                    if 'script' not in list(scan_result['scan'][host][proto][port].keys()):
                        scan_result['scan'][host][proto][port]['script'] = {}

                    scan_result['scan'][host][proto][port]['script'][script_id] = script_out

            for dhostscript in dhost.findall('hostscript'):
                for dname in dhostscript.findall('script'):
                    hsid = dname.get('id')
                    hsoutput = dname.get('output')

                    if 'hostscript' not in list(scan_result['scan'][host].keys()):
                        scan_result['scan'][host]['hostscript'] = []

                    scan_result['scan'][host]['hostscript'].append(
                        {
                            'id': hsid,
                            'output': hsoutput
                        }
                    )

            for dos in dhost.findall('os'):
                osmatch = []
                portused = []
                for dportused in dos.findall('portused'):
                    # <portused state="open" proto="tcp" portid="443"/>
                    state = dportused.get('state')
                    proto = dportused.get('proto')
                    portid = dportused.get('portid')
                    portused.append({
                        'state': state,
                        'proto': proto,
                        'portid': portid,
                    })

                scan_result['scan'][host]['portused'] = portused

                for dosmatch in dos.findall('osmatch'):
                    name = dosmatch.get('name')
                    accuracy = dosmatch.get('accuracy')
                    line = dosmatch.get('line')

                    osclass = []
                    for dosclass in dosmatch.findall('osclass'):
                        ostype = dosclass.get('type')
                        vendor = dosclass.get('vendor')
                        osfamily = dosclass.get('osfamily')
                        osgen = dosclass.get('osgen')
                        accuracy = dosclass.get('accuracy')

                        cpe = []
                        for dcpe in dosclass.findall('cpe'):
                            cpe.append(dcpe.text)

                        osclass.append({
                            'type': ostype,
                            'vendor': vendor,
                            'osfamily': osfamily,
                            'osgen': osgen,
                            'accuracy': accuracy,
                            'cpe': cpe,
                        })

                    osmatch.append({
                        'name': name,
                        'accuracy': accuracy,
                        'line': line,
                        'osclass': osclass
                    })
                else:
                    scan_result['scan'][host]['osmatch'] = osmatch

            for dport in dhost.findall('osfingerprint'):
                fingerprint = dport.get('fingerprint')

                scan_result['scan'][host]['fingerprint'] = fingerprint

        self._scan_result = scan_result  # store for later use
        return scan_result

    def __getitem__(self, host):
        assert type(host) is str, 'Wrong type for [host], should be a string [was {0}]'.format(type(host))
        return self._scan_result['scan'][host]

    def all_hosts(self):
        if 'scan' not in list(self._scan_result.keys()):
            return []
        listh = list(self._scan_result['scan'].keys())
        listh.sort()
        return listh

    def command_line(self):
        assert 'nmap' in self._scan_result, 'Do a scan before trying to get result !'
        assert 'command_line' in self._scan_result['nmap'], 'Do a scan before trying to get result !'

        return self._scan_result['nmap']['command_line']

    def scaninfo(self):
        assert 'nmap' in self._scan_result, 'Do a scan before trying to get result !'
        assert 'scaninfo' in self._scan_result['nmap'], 'Do a scan before trying to get result !'

        return self._scan_result['nmap']['scaninfo']

    def scanstats(self):
        assert 'nmap' in self._scan_result, 'Do a scan before trying to get result !'
        assert 'scanstats' in self._scan_result['nmap'], 'Do a scan before trying to get result !'

        return self._scan_result['nmap']['scanstats']

    def has_host(self, host):
        assert type(host) is str, 'Wrong type for [host], should be a string [was {0}]'.format(type(host))
        assert 'scan' in self._scan_result, 'Do a scan before trying to get result !'

        if host in list(self._scan_result['scan'].keys()):
            return True

        return False

    def csv(self):
        assert 'scan' in self._scan_result, 'Do a scan before trying to get result !'

        fd = io.StringIO()

        csv_ouput = csv.writer(fd, delimiter=';')
        csv_header = [
            'host',
            'hostname',
            'hostname_type',
            'protocol',
            'port',
            'name',
            'state',
            'product',
            'extrainfo',
            'reason',
            'version',
            'conf',
            'cpe'
        ]

        csv_ouput.writerow(csv_header)

        for host in self.all_hosts():
            for proto in self[host].all_protocols():
                if proto not in ['tcp', 'udp']:
                    continue
                lport = list(self[host][proto].keys())
                lport.sort()
                for port in lport:
                    hostname = ''
                    for h in self[host]['hostnames']:
                        hostname = h['name']
                        hostname_type = h['type']
                        csv_row = [
                            host, hostname, hostname_type,
                            proto, port,
                            self[host][proto][port]['name'],
                            self[host][proto][port]['state'],
                            self[host][proto][port]['product'],
                            self[host][proto][port]['extrainfo'],
                            self[host][proto][port]['reason'],
                            self[host][proto][port]['version'],
                            self[host][proto][port]['conf'],
                            self[host][proto][port]['cpe']
                        ]
                        csv_ouput.writerow(csv_row)

        return fd.getvalue()


def __scan_progressive__(self, hosts, ports, arguments, callback, sudo):
    for host in self._nm.listscan(hosts):
        try:
            scan_data = self._nm.scan(host, ports, arguments, sudo)
        except PortScannerError:
            scan_data = None

        if callback is not None:
            callback(host, scan_data)
    return


class PortScannerAsync(object):
    def __init__(self):
        self._process = None
        self._nm = PortScanner()
        return

    def __del__(self):
        if self._process is not None:
            try:
                if self._process.is_alive():
                    self._process.terminate()
            except AssertionError:
                # Happens on python3.4
                # when using PortScannerAsync twice in a row
                pass

        self._process = None
        return

    def scan(self, hosts='127.0.0.1', ports=None, arguments='-sV', callback=None, sudo=False):
        assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
        assert type(ports) in (str, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(
            type(ports))
        assert type(arguments) is str, 'Wrong type for [arguments], should be a string [was {0}]'.format(
            type(arguments))
        assert callable(callback) or callback is None, 'The [callback] {0} should be callable or None.'.format(
            str(callback))

        for redirecting_output in ['-oX', '-oA']:
            assert redirecting_output not in arguments, 'Xml output can\'t be redirected from command line.\nYou can access it after a scan using:\nnmap.nm.get_nmap_last_output()'

        self._process = Process(
            target=__scan_progressive__,
            args=(self, hosts, ports, arguments, callback, sudo)
        )
        self._process.daemon = True
        self._process.start()
        return

    def stop(self):
        if self._process is not None:
            self._process.terminate()
        return

    def wait(self, timeout=None):
        assert type(timeout) in (
        int, type(None)), 'Wrong type for [timeout], should be an int or None [was {0}]'.format(type(timeout))

        self._process.join(timeout)
        return

    def still_scanning(self):
        try:
            return self._process.is_alive()
        except:
            return False


class PortScannerYield(PortScannerAsync):
    def __init__(self):
        PortScannerAsync.__init__(self)
        return

    def scan(self, hosts='127.0.0.1', ports=None, arguments='-sV', sudo=False):
        assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
        assert type(ports) in (str, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(
            type(ports))
        assert type(arguments) is str, 'Wrong type for [arguments], should be a string [was {0}]'.format(
            type(arguments))

        for redirecting_output in ['-oX', '-oA']:
            assert redirecting_output not in arguments, 'Xml output can\'t be redirected from command line.\nYou can access it after a scan using:\nnmap.nm.get_nmap_last_output()'

        for host in self._nm.listscan(hosts):
            try:
                scan_data = self._nm.scan(host, ports, arguments, sudo)
            except PortScannerError:
                scan_data = None
            yield (host, scan_data)
        return

    def stop(self):
        pass

    def wait(self, timeout=None):
        pass

    def still_scanning(self):
        pass


class PortScannerHostDict(dict):
    def hostnames(self):
        return self['hostnames']

    def hostname(self):
        hostname = ''
        for h in self['hostnames']:
            if h['type'] == 'user':
                return h['name']
        else:
            if len(self['hostnames']) > 0 and 'name' in self['hostnames'][0]:
                return self['hostnames'][0]['name']
            else:
                return ''
        return hostname

    def state(self):
        return self['status']['state']

    def uptime(self):
        return self['uptime']

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

        return type_ not in list(self.keys()) and port in list(self[type_].keys())

    def _port(self, type_, port):
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))
        return self[type_][port]

    all_tcp = functools.partial(_all_porttype, 'tcp')
    has_tcp = functools.partial(_has_port, 'tcp')
    tcp = functools.partial(_port, 'tcp')

    all_udp = functools.partial(_all_porttype, 'udp')
    has_udp = functools.partial(_has_port, 'udp')
    udp = functools.partial(_port, 'udp')

    all_ip = functools.partial(_all_porttype, 'ip')
    has_ip = functools.partial(_has_port, 'ip')
    ip = functools.partial(_port, 'ip')

    all_sctp = functools.partial(_all_porttype, 'sctp')
    has_sctp = functools.partial(_has_port, 'sctp')
    sctp = functools.partial(_port, 'sctp')


class PortScannerError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

    def __repr__(self):
        return 'PortScannerError exception {0}'.format(self.value)


def __get_last_online_version():
    import http.client
    conn = http.client.HTTPConnection("xael.org")
    conn.request("GET", "/pages/python-nmap/python-nmap_CURRENT_VERSION.txt")
    online_version = bytes.decode(conn.getresponse().read()).strip()
    return online_version


def convert_nmap_output_to_encoding(value, code="ascii"):
    new_value = {}
    for k in value:
        if type(value[k]) in [dict, PortScannerHostDict]:
            new_value[k] = convert_nmap_output_to_encoding(value[k], code)
        else:
            if type(value[k]) is list:
                new_value[k] = [
                    convert_nmap_output_to_encoding(x, code) for x in value[k]
                ]
            else:
                new_value[k] = value[k].encode(code)
    return new_value
