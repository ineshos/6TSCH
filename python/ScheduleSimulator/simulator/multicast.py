import logging
import optparse
import socket
import struct
import sys
import time
import traceback

IP4_ADDR_ANY = '0.0.0.0'  # socket.INADDR_ANY
DATA_FMT = "%(seq)09d %(time)s %(data)s"


class MulticastSocket(socket.socket):
    """Multicast Socket object to send/receive multicast packets easily.
    """

    def __init__(self, grp_addr, if_addr=IP4_ADDR_ANY, ttl=1):
        """
        @param  grp_addr:  Multicast network address
        @param  if_addr:   Interface address to use for.
        @param  ttl:       time to live.
        SEE ALSO: getsockopt(2), ip(7)
        """
        socket.socket.__init__(self, socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

        self.mreq = socket.inet_aton(grp_addr) + socket.inet_aton(if_addr)

        if if_addr != IP4_ADDR_ANY:
            # Specify the interface to send packets.
            self.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(if_addr))
        else:
            # The interface to send packets will be selected by kernel
            # automatically.
            pass

        if ttl > 1:
            self.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL,
                            struct.pack('b', ttl))

        self.grp_addr = grp_addr
        self.if_addr = if_addr

    def __del__(self):
        """Destructor.
        """
        self.leave()
        self.close()

    def join(self):
        """
        FIXME: Check the return value of setsockopt.
        Unfortunately, the following code does not work because
        socket.getsockopt will return None.
        if self.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP,
                           self.mreq) != 0:
            logging.error("Could not join '%s' on '%s:%d'",
                          grp_addr, if_addr, port)
        """
        self.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, self.mreq)
        logging.debug("Joined the multicast network: %s on %s",
                      self.grp_addr, self.if_addr)

    def leave(self):
        """
        Likewise (see above note).
        """
        self.setsockopt(socket.SOL_IP, socket.IP_DROP_MEMBERSHIP, self.mreq)
        logging.debug("Left the multicast network: %s on %s",
                      self.grp_addr, self.if_addr)


def dump_stat(packets):
    """Dump packets stat.
    """
    for cli, seqs in packets.iteritems():
        cli_s = "%s:%d" % cli
        rcvd = ["#%d" % i for i in seqs]
        lost = ["#%d" % i for i in range(1, max(seqs)) if i not in seqs]
        (rcvd_n, lost_n) = (len(rcvd), len(lost))
        # (rcvd_s, lost_s) = (", ".join(rcvd), ", ".join(lost))
        logging.info("%s: Received=%d, (maybe) Lost=%d",
                     cli_s, rcvd_n, lost_n)


class MulticastServer(object):
    """Multicast Server object to join multicast networks and listen forever.
    """

    def __init__(self, grp_addr, port, if_addr=IP4_ADDR_ANY, ttl=1,
                 reuse=False):
        """
        @param  grp_addr:  Multicast network address
        @param  if_addr:   Interface address to use for.
        @param  ttl:       time to live.
        @param  reuse:     socket reuse flag.
        SEE ALSO: getsockopt(2), ip(7)
        """
        self.sock = MulticastSocket(grp_addr, if_addr, ttl)

        if reuse:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        self.sock.bind(('', port))
        logging.debug("Bound: %s:%d", self.sock.if_addr, port)

        self.sock.join()

    def __del__(self):
        """Destructor.
        """
        del self.sock

    def loop(self, interval=1):
        """Main event loop.
        """
        packets = dict()

        try:
            while True:
                (segment, (ip4_addr, port)) = self.sock.recvfrom(1024)

                if not segment:
                    logging.info("Exiting as received an empty packet...")
                    sys.exit(0)

                tup = segment.split()
                if len(tup) < 3:
                    logging.info("Exiting as received an empty data packet...")
                    sys.exit(0)

                # @see DATA_FMT
                (seq, time_sent, data) = tup
                try:
                    seq = int(seq)
                    time_sent = float(time_sent)
                except ValueError:
                    logging.warn("Received unexpected formatted data. Skip it")
                    continue

                last_seqs = packets.get((ip4_addr, port), [])
                if last_seqs:
                    last_seq = last_seqs[-1]
                else:
                    last_seq = 0
                    packets[(ip4_addr, port)] = []

                delta = time.time() - time_sent
                from_s = "from %s:%d" % (ip4_addr, port)

                logging.info("Received '%s' (#%d) %s, time=%f",
                             data, seq, from_s, delta)

                if seq < last_seq:
                    logging.debug("Inversion! #%d %s is younger than last one "
                                  "(#%d).", seq, from_s, last_seq)
                elif seq == last_seq:
                    logging.debug("DUP segment! #%d %s", seq, from_s)
                else:
                    if seq > (last_seq + 1):
                        last_received = packets[(ip4_addr, port)]
                        losts = ["#%d" % i for i in range(last_seq + 1, seq)
                                 if i not in last_received]
                        losts_s = ", ".join(losts)
                        logging.debug("LOST segments! %s %s", losts_s, from_s)

                packets[(ip4_addr, port)].append(seq)
                # TODO: Send back to client.
                # ssize = self.sock.sendto(segment, (ip4_addr, port))
                # if ssize < len(segment):
                #    logging.warn("Failed to send back to the client: %s "
                #                 "(port: %d)", ip4_addr, port)
                time.sleep(interval)

        except (KeyboardInterrupt, SystemExit):
            logging.info("Exiting...")
            dump_stat(packets)
        except:
            traceback.print_exc()

    def run(self):
        """Server main.
        """
        self.loop()


class MulticastClient(object):
    """Multicast Client object to send packets to multicast network.
    """

    def __init__(self, grp_addr, port, if_addr=IP4_ADDR_ANY, ttl=1,
                 datafmt=DATA_FMT):
        """
        @param  grp_addr:  Multicast network address
        @param  if_addr:   Interface address to use for.
        @param  ttl:       time to live.
        SEE ALSO: getsockopt(2), ip(7)
        """
        self.sock = MulticastSocket(grp_addr, if_addr, ttl)
        self.grp_addr = grp_addr
        self.port = port
        self.datafmt = datafmt

        if if_addr != IP4_ADDR_ANY:
            self.sock.join() # I think this is necessary for such cases.

    def loop(self, data, count=0, interval=1):
        """Main event loop.
        """
        try:
            seq = 1

            while True:
                segment = self.datafmt % {'seq':seq, 'time':time.time(),
                                          'data': data}
                ssize = self.sock.sendto(segment, (self.grp_addr, self.port))

                if ssize < len(segment):
                    logging.warn("Failed to send: '%s'", segment)
                else:
                    logging.info("Sent data: '%s'", segment)

                if count > 0 and seq >= count:
                    return ssize == len(segment)

                seq += 1
                time.sleep(interval)

        except (KeyboardInterrupt, SystemExit):
            logging.info("Exiting...")
        except:
            traceback.print_exc()


def opts_parser(mcast_addr_default, port_default):
    """Option parser.
    """
    psr = optparse.OptionParser("%prog [OPTION ...]\n\n"
                                "  Server mode: %prog [OPTION ...],\n"
                                "  Client mode: %prog [OPTION ...] "
                                "[DATA_TO_SEND]")

    psr.add_option('-s', '--server', action="store_true", default=False,
                   help='Server mode. [Default: client mode]')

    # options in jgroup's test code:
    # common: bind_addr, mcast_addr, port, (receive|send)_on_all_interfaces
    # server (receiver): no unique options
    # client (sender): ttl
    psr.add_option('-M', '--mcast_addr', default=mcast_addr_default,
                   dest='mcast_addr',
                   help='Multicast network address to join/sendto. [%default]')
    psr.add_option('-I', '--if_addr', default=IP4_ADDR_ANY, dest='if_addr',
                   help="Interface address to listen on. [IPv4 ADDR_ANY, i.e. "
                        "automatically selected]")
    psr.add_option('-p', '--port', default=port_default, type="int",
                   help='Port to listen on/connect. [%default]')
    psr.add_option('-t', '--ttl', default=1, type="int",
                   help='Time-to-live for multicast packets [%default]')

    psr.add_option('-q', '--quiet', action="store_true",
                   help="Quiet mode; suppress debug message")

    sog = optparse.OptionGroup(psr, "Options for server mode")
    sog.add_option('-r', '--reuse', action="store_true", default=False,
                   help='Reuse socket? [no]')
    psr.add_option_group(sog)

    cog = optparse.OptionGroup(psr, "Options for client mode")
    cog.add_option('-c', '--count', type="int", default=0,
                   help="Stop after sending COUNT packets. By default, it "
                        "will send packets forever [%default].")
    cog.add_option('-i', '--interval', type="int", default=1,
                   help="Wait  interval  seconds between sending each "
                        "packet. [%default].")
    psr.add_option_group(cog)

    return psr


def main():
    """Entry point.
    """
    logformat = '%(asctime)s %(levelname)-8s %(message)s'
    logdatefmt = '%a, %d %b %Y %H:%M:%S'

    mcast_addr = '229.192.0.1'  # cman default; cman(5)
    port = 5405                 # likewise

    parser = opts_parser(mcast_addr, port)
    (options, args) = parser.parse_args()

    if options.quiet:
        loglevel = logging.INFO
    else:
        loglevel = logging.DEBUG

    try:
        # logging.basicConfig() in python older than 2.4 cannot handle kwargs,
        # then exception 'TypeError' will be thrown.
        logging.basicConfig(level=loglevel, format=logformat,
                            datefmt=logdatefmt)
    except TypeError:
        # To keep backward compatibility. See above comment also.
        logging.getLogger().setLevel(loglevel)

    if options.server:
        srv = MulticastServer(options.mcast_addr,
                              options.port,
                              options.if_addr,
                              options.ttl,
                              options.reuse)
        srv.run()
    else:
        try:
            if len(args) > 0:
                data = args[0]
            else:
                data = raw_input('Type any to sendto > ')
        except EOFError:
            sys.exit(0)

        cli = MulticastClient(options.mcast_addr, options.port, options.if_addr,
                              options.ttl)
        cli.loop(data, options.count, options.interval)


if __name__ == '__main__':
    main()
