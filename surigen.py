#!/usr/bin/python3
# Copyright 2013, 2014, 2017 Conix Cybersécurité
# Copyright 2013 Adrien Chevalier (bl2ru)
# Copyright 2013, 2014 Alexandre Deloup (bl2ru)
# Copyright 2017 Robin Marsollier
# Copyright 2017 Michael Muenz
# Copyright 2026 Konstantinos Spartalis
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import argparse
import os
import re

#####
# To add a rule class while keeping the code clean:
# 1. add the base rule thereafter
# 2. create the gen_SMTHG_rule() function that is going to generate the rules
#        using the baserule defined before
# 3. modify the __generate_rules__() function to call your new generator
#
# Format positions for all rules:
#   IP rules:   {0}=dest_ip, {1}=org, {2}=name, {3}=dest_ip, {4}=ref, {5}=classtype, {6}=sid
#   DNS rule:   {0}=org, {1}=name, {2}=domain,  {3}=domain,  {4}=ref, {5}=classtype, {6}=sid
#   URL rule:   {0}=org, {1}=name, {2}=uri, {3}=uri, {4}=extra_content, {5}=ref, {6}=classtype, {7}=sid
#   TLS rule:   {0}=org, {1}=name, {2}=domain,  {3}=domain,  {4}=ref, {5}=classtype, {6}=sid
#   MD5 rule:   {0}=org, {1}=name, {2}=basename, {3}=filepath, {4}=ref, {5}=classtype, {6}=sid
#####

IP_UDP_BASERULE = (
    'alert udp $HOME_NET any -> {0} any '
    '(msg:"{1} - {2} - UDP traffic to {3}"; '
    'reference:url,{4}; classtype:{5}; sid:{6}; rev:1;)'
)
IP_TCP_BASERULE = (
    'alert tcp $HOME_NET any -> {0} any '
    '(msg:"{1} - {2} - TCP traffic to {3}"; '
    'flow:to_server,established; reference:url,{4}; classtype:{5}; sid:{6}; rev:1;)'
)
IP_BASERULE = (
    'alert ip $HOME_NET any -> {0} any '
    '(msg:"{1} - {2} - IP traffic to {3}"; '
    'reference:url,{4}; classtype:{5}; sid:{6}; rev:1;)'
)
DNS_BASERULE = (
    'alert dns $HOME_NET any -> any 53 '
    '(msg:"{0} - {1} - DNS request for {2}"; '
    'dns.query; content:"{3}"; nocase; '
    'reference:url,{4}; classtype:{5}; sid:{6}; rev:1;)'
)
URL_BASERULE = (
    'alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS '
    '(msg:"{0} - {1} - Related URL ({2})"; '
    'http.uri; content:"{3}";{4} '
    'flow:to_server,established; reference:url,{5}; classtype:{6}; sid:{7}; rev:1;)'
)
TLS_BASERULE = (
    'alert tls $HOME_NET any -> $EXTERNAL_NET any '
    '(msg:"{0} - {1} - Related TLS SNI ({2})"; '
    'tls.sni; content:"{3}"; '
    'flow:to_server,established; reference:url,{4}; classtype:{5}; sid:{6}; rev:1;)'
)
MD5_BASERULE = (
    'alert tcp any [$HTTP_PORTS, 25] -> $HOME_NET any '
    '(msg:"{0} - {1} - MD5 hash found in blacklist {2}"; '
    'filestore; filemd5:{3}; '
    'reference:url,{4}; classtype:{5}; sid:{6}; rev:1;)'
)

# Regex for a bare IPv4 address (no CIDR, no trailing chars)
_IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')


class Surigen:
    def __init__(self, org, sid, classtype):
        '''
        Initialise org, classtype, and the starting SID for this run.
        org and classtype are always set first so __del__ never fires
        against uninitialised state even if we return early.
        '''
        self._org_ = org
        self._classtype_ = classtype
        self._sid_ = 5100000  # safe default

        if not sid:
            try:
                with open(".sid_log_file", "r", encoding="utf-8") as f:
                    self._sid_ = int(f.readline().strip())
            except FileNotFoundError:
                print("[-] .sid_log_file not found, starting SID from 5100000")
            except PermissionError as err:
                print(err)
                print("[+] Aborting!")
                quit(0)
        else:
            self._sid_ = sid

    def __del__(self):
        '''
        Save the next-available SID for the following run.
        '''
        try:
            with open(".sid_log_file", "w", encoding="utf-8") as f:
                f.write(str(self._sid_))
        except PermissionError as err:
            print(err)
            print("[-] sid not saved, be careful")
            return False
        return True

    def _next_sid(self):
        sid = self._sid_
        self._sid_ += 1
        return sid

    def gen_dns_rule(self, name, domain, ref):
        '''Generate a Suricata rule matching a DNS query for domain.'''
        sid = self._next_sid()
        rule = DNS_BASERULE.format(
            self._org_, name, domain, domain, ref, self._classtype_, sid
        )
        return rule, sid

    def gen_uri_rule(self, name, url, ref):
        '''Generate a Suricata rule matching an HTTP URI.'''
        uri = url.split("?")[0]
        uri_params = "?".join(url.split("?")[1:])
        extra = ""
        if uri_params:
            params = uri_params.split("&")
            extra = ' content:"?{}=";'.format(params[0].split("=")[0])
            for param in params[1:]:
                param = param.replace(';', r'|3b|')
                extra += ' content:"&{}=";'.format(param.split("=")[0])
        sid = self._next_sid()
        rule = URL_BASERULE.format(
            self._org_, name, uri, uri, extra, ref, self._classtype_, sid
        )
        return rule, sid

    def gen_ip_rule_udp(self, name, ip_addr, ref):
        '''Generate a Suricata rule for UDP traffic to an IP.'''
        sid = self._next_sid()
        rule = IP_UDP_BASERULE.format(
            ip_addr, self._org_, name, ip_addr, ref, self._classtype_, sid
        )
        return rule, sid

    def gen_ip_rule_tcp(self, name, ip_addr, ref):
        '''Generate a Suricata rule for TCP traffic to an IP.'''
        sid = self._next_sid()
        rule = IP_TCP_BASERULE.format(
            ip_addr, self._org_, name, ip_addr, ref, self._classtype_, sid
        )
        return rule, sid

    def gen_ip_rule(self, name, ip_addr, ref):
        '''Generate a Suricata rule for any IP traffic to an IP.'''
        sid = self._next_sid()
        rule = IP_BASERULE.format(
            ip_addr, self._org_, name, ip_addr, ref, self._classtype_, sid
        )
        return rule, sid

    def gen_tls_rule(self, name, domain, ref):
        '''Generate a Suricata rule matching a TLS SNI for domain.'''
        sid = self._next_sid()
        rule = TLS_BASERULE.format(
            self._org_, name, domain, domain, ref, self._classtype_, sid
        )
        return rule, sid

    def gen_md5_rule(self, name, filepath, ref):
        '''
        Generate a Suricata rule checking file MD5 against a hash list.
        filepath must point to a file containing one MD5 per line.
        '''
        sid = self._next_sid()
        rule = MD5_BASERULE.format(
            self._org_, name, os.path.basename(filepath), filepath,
            ref, self._classtype_, sid
        )
        return rule, sid


def __split_line__(line):
    '''
    Split a whitespace-delimited input line into (name, ioc, ref_url).
    Expected column order: name  ref_url  ioc
    Returns ("", "", "") for malformed lines.
    '''
    parts = line.split()
    if len(parts) < 3:
        return "", "", ""
    return parts[0], parts[2], parts[1]


def __generate_rules__(gen, csv_file):
    '''
    Read the IOC file and dispatch each entry to the appropriate generator.
    '''
    try:
        with open(csv_file, "r", encoding="utf-8") as f_input:
            rules = []
            for line in f_input:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                name, ioc, ref_url = __split_line__(line)
                if not name:
                    continue

                if (ioc.startswith("/") or ioc.startswith("http")) and not os.path.isfile(ioc):
                    # Looks like a URI path or full URL
                    rule, _ = gen.gen_uri_rule(name, ioc, ref_url)
                    rules.append(rule)

                elif _IP_RE.match(ioc):
                    # Bare IPv4 address (CIDR notation falls through to FQDN branch)
                    rule, _ = gen.gen_ip_rule(name, ioc, ref_url)
                    rules.append(rule)

                elif os.path.isfile(ioc):
                    # Path to a file of MD5 hashes
                    rule, _ = gen.gen_md5_rule(name, ioc, ref_url)
                    rules.append(rule)

                else:
                    # Treat as FQDN: emit DNS + HTTP + TLS rules
                    rule, _ = gen.gen_dns_rule(name, ioc, ref_url)
                    rules.append(rule)
                    rule, _ = gen.gen_uri_rule(name, ioc, ref_url)
                    rules.append(rule)
                    rule, _ = gen.gen_tls_rule(name, ioc, ref_url)
                    rules.append(rule)

    except PermissionError as err:
        print(err)
        print("[+] Aborting!")
        quit(0)

    return rules


def main(args):
    gen = Surigen(args.emitter, args.ssid, args.classtype)

    if args.output:
        print("[+] Generating rules")
    rules = __generate_rules__(gen, args.file)

    if args.output:
        print("[+] Writing rule file")
        try:
            with open(args.output, "a", encoding="utf-8") as f_out:
                for rule in rules:
                    f_out.write(rule + "\n")
        except PermissionError:
            print("[+] Can't write rule file, permission denied")
            print("[+] Rules not saved, be careful")
    else:
        for rule in rules:
            print(rule)


if __name__ == '__main__':
    __parser__ = argparse.ArgumentParser(
        description="Generate Suricata 8+ rules from an IOC list."
    )
    __parser__.add_argument("file",
                            help="Input file (columns: name  ref_url  ioc)")
    __parser__.add_argument("--output", "-o",
                            help="Output file (default: stdout)")
    __parser__.add_argument("--ssid", "-s",
                            help="Starting SID (default: read from .sid_log_file)",
                            type=int)
    __parser__.add_argument("--emitter", "-e",
                            help="Rule emitter/org tag (default: surigen)",
                            default="surigen")
    __parser__.add_argument("--classtype", "-c",
                            help="Suricata classtype for all generated rules "
                                 "(default: policy-violation)",
                            default="policy-violation")
    __args__ = __parser__.parse_args()
    main(__args__)
