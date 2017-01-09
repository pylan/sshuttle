import socket
from sshuttle.helpers import family_to_string
from sshuttle.linux import ipt, ipt_ttl, ipt_chain_exists, nonfatal
from sshuttle.methods import BaseMethod
import netifaces as ni


class Method(BaseMethod):

    # We name the chain based on the transproxy port number so that it's
    # possible to run multiple copies of sshuttle at the same time.  Of course,
    # the multiple copies shouldn't have overlapping subnets, or only the most-
    # recently-started one will win (because we use "-I OUTPUT 1" instead of
    # "-A OUTPUT").
    def setup_firewall(self, port, dnsport, nslist, family, subnets, udp):
        # only ipv4 supported with NAT
        if family != socket.AF_INET:
            raise Exception(
                'Address family "%s" unsupported by nat method_name'
                % family_to_string(family))
        if udp:
            raise Exception("UDP not supported by nat method_name")

        table = "nat"

        def _ipt(*args):
            return ipt(family, table, *args)

        def _ipt_ttl(*args):
            return ipt_ttl(family, table, *args)

        chain = 'sshuttle-%s' % port

        # basic cleanup/setup of chains
        self.restore_firewall(port, family, udp)

        _ipt('-N', chain)
        _ipt('-F', chain)
        _ipt('-I', 'OUTPUT', '1', '-j', chain)
        _ipt('-I', 'PREROUTING', '1', '-j', chain)

        # add a rule as the first entry to not route packets that are
        # generated locally though sshuttle
        ni.ifaddresses('eth0')
        ip = ni.ifaddresses('eth0')[2][0]['addr']
        _ipt('-A', chain, '-j', 'RETURN',
             '--src', '%s/32' % ip)

        # add a rule to route requests to 1.0.0.0 to localhost
        _ipt('-t', 'nat', '-A', 'PREROUTING', '-d', '1.0.0.0',  '-j', 'DNAT', 
             '--to-destination', '127.0.0.1')

        # create new subnet entries.  Note that we're sorting in a very
        # particular order: we need to go from most-specific (largest
        # swidth) to least-specific, and at any given level of specificity,
        # we want excludes to come first.  That's why the columns are in
        # such a non- intuitive order.
        for f, swidth, sexclude, snet \
                in sorted(subnets, key=lambda s: s[1], reverse=True):
            if sexclude:
                _ipt('-A', chain, '-j', 'RETURN',
                     '--dest', '%s/%s' % (snet, swidth),
                     '-p', 'tcp')
            else:
                _ipt_ttl('-A', chain, '-j', 'REDIRECT',
                         '--dest', '%s/%s' % (snet, swidth),
                         '-p', 'tcp',
                         '--to-ports', str(port))

        for f, ip in [i for i in nslist if i[0] == family]:
            _ipt_ttl('-A', chain, '-j', 'REDIRECT',
                     '--dest', '%s/32' % ip,
                     '-p', 'udp',
                     '--dport', '53',
                     '--to-ports', str(dnsport))

    def restore_firewall(self, port, family, udp):
        # only ipv4 supported with NAT
        if family != socket.AF_INET:
            raise Exception(
                'Address family "%s" unsupported by nat method_name'
                % family_to_string(family))
        if udp:
            raise Exception("UDP not supported by nat method_name")

        table = "nat"

        def _ipt(*args):
            return ipt(family, table, *args)

        def _ipt_ttl(*args):
            return ipt_ttl(family, table, *args)

        chain = 'sshuttle-%s' % port

        # remove rule to route requests to 1.0.0.0 to localhost
        nonfatal(_ipt, '-D', 'PREROUTING', '-d', '1.0.0.0',  '-j', 'DNAT',
                 '--to-destination', '127.0.0.1')

        # basic cleanup/setup of chains
        if ipt_chain_exists(family, table, chain):
            nonfatal(_ipt, '-D', 'OUTPUT', '-j', chain)
            nonfatal(_ipt, '-D', 'PREROUTING', '-j', chain)
            nonfatal(_ipt, '-F', chain)
            _ipt('-X', chain)
