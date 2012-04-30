#!/usr/bin/python2.6

"""
xbox 360 connect - transparent proxy over SSH
Copyright (C) 2010 Leif Theden <leif.theden@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

# the author is not affiliated or connected with microsoft,
# or xbox live. xbox (360) is a trademark of microsoft corp.

# WARNING: Use of this script will erase your current routing rules.
#          Please modify this script if you have special routing needs.

#  VERSION  .002

# because we are forwarding priviligded ports and configuring
# interfaces, this script must be run as root or another user
# with those rights.  try sudo.
# disable network-manager!

# ports used by xbox live
#	TCP 80
#	UDP 88
#	UDP 3074
#	TCP 3074
#	UDP 53
#	TCP 53

# special thanks to leonid evdokimov for redsocks

from subprocess import PIPE, STDOUT
import subprocess
import os.path
import socket
import fcntl
import struct
import re
import sys 
import time
import uuid

global options


"""
modes of operation:

1 - connect xbox on wired connection to wireless (bridge)
2 - proxy xbox through existing socks5 server (proxy)
3 - tunnel xbox through new ssh connection (ssh tunnel)

"""

# simple way to store defaults
class Options(object):
	pass

defaults = Options()
options  = Options()

# enable coloring of output
defaults.use_color = True

# if you specify the MAC of the xbox, ports can be forwarded automatically
# please use the xx:xx:xx:xx:xx:xx format
#xbox_mac = "00:00:00:00:00:00"
# Not Implemented.  Changing this value will have no effect.
defaults.xbox_mac = None
#xbox_mac = "00:25:ae:05:37:65"

# if the mac is set, then the following ports are forwarded to the host.
# this is needed to have a "open" nat status for live.
# if the host pc is also on a nat'd network make sure ports are also
# forwarded to the host on the router.
defaults.live_ports = \
	["tcp:53", "udp:53", "tcp:80", "udp:88", "tcp:3074", "udp:3074"]

# these ports on the host will not be forwarded to the internet.
# useful if you want to run a server on your host that is available
# to clients on the lan side.  like...ssh, ftp, etc.
defaults.reserve_ports = [22]

# If True, then traffic from the host will be tunneled with lan side
# Initially set to False to conserve bandwith
defaults.forward_host = False

# default port for iptables to forward packets to redsocks.
defaults.redsocks_port = 12345

# if using a proxy it should be either "socks4" or "socks5"
# when using SSH, it will should be "socks5"
defaults.socks_type = "socks5"

# interface to listen on for the xbox
defaults.lan_if     = "eth0"

# interface that is connected to the internet
defaults.wan_if      = "wlan0"

# adjust accordingly (socks = ssh)
# defaults are ok for a tunneled connection
# currently, socks authentication is not supported
defaults.use_socks     = False
defaults.socks_host    = "127.0.0.1"
defaults.socks_port    = 1080
defaults.socks_user    = None
defaults.socks_type    = "socks5"
defaults.socks_password = None

# SSH Login Information
defaults.use_ssh  = False
defaults.ssh_host = ""
defaults.ssh_port = 443
defaults.ssh_user = ""

# Add your own flags to ssh if you want (-N included already)
# using compression (-C) doesn't help and may lower your bandwidth 
defaults.ssh_opt     = "" 

# dnsmasq options
defaults.dhcp_lease  = "12h"
defaults.dhcp_pool   = 10

# script can attept to configure the interface if not already set up
defaults.auto_config = False

# enable extra output (0-4)
defaults.verbosity = 2

# make our options work
options.__dict__.update(defaults.__dict__)


# adjust according to your system
dnsmasq_bin  = "/usr/sbin/dnsmasq"
ssh_bin      = "/usr/bin/ssh"
ifconfig_bin = "/sbin/ifconfig"
redsocks_bin = "./redsocks"
shell_bin    = "/bin/sh"

# for help.  % = newline
epilog = """
HOST is formatted as user@host:port.  eg: coolkid4@freessh.net:443.%%
Both user and port may be left out.  Defaults will be used.%
Note that socks authentication isn't (yet) supported.
"""

def get_ip_address(name):
	if name == None:
		return

	try:
		return socket.gethostbyname(name)	
	except:
		bail("Cannot get ip address for ssh host %s" % options.ssh_host)

# get terminal width
# from: http://pdos.csail.mit.edu/~cblake/cls/cls.py
def ioctl_GWINSZ():
	try:
		import fcntl, termios, struct, os
		fd = os.open(os.ctermid(), os.O_RDONLY)
		cr = struct.unpack('hh', fcntl.ioctl(fd, termios.TIOCGWINSZ, '1234'))
	except:
		return (25, 80)
	return cr

def handle_arguments():
	from optparse import OptionParser, OptionGroup, OptionValueError
	sys.path.append( os.path.abspath( '..' ) )

	def option_callback(option, opt_str, value, parser, *args, **kwargs):
		pass

	def parse_host(text):
		if "@" in text:
			user = text[:text.index("@")]
			if ":" in text:
				host = text[text.index("@") +1 :text.index(":")]
				port = int(text[text.index(":") +1 :])
			else:
				host = text[text.index("@") +1 :]
				port = options.socks_port
		else:
			user = None
			if ":" in text:
				host = text[:text.index(":")]
				port = int(text[text.index(":") +1 :])
			else:
				host = text
				port = options.socks_port

		return user, host, port

	def check_ssh(option, opt, value, parser):
		try:
			if option.dest == "ssh_host":
				if parser.values.use_socks:
					raise OptionValueError("Cannot use both SSH and SOCKS proxy")
	
			if option.dest == "socks_host":
				if parser.values.use_ssh:
					raise OptionValueError("Cannot use both SSH and SOCKS proxy")
		except AttributeError:
			pass

	def check_socks_host(option, opt, value, parser):
		check_ssh(option, opt, value, parser)
		try:
			u, h, p = parse_host(value)
		except ValueError:
			raise OptionValueError("socks host string is improperly formatted")
		else:
			parser.values.socks_user = u
			parser.values.socks_host = h
			parser.values.socks_port = p
			parser.values.use_socks  = True

	def check_ssh_host(option, opt, value, parser):
		check_ssh(option, opt, value, parser)
		try:
			u, h, p = parse_host(value)
		except ValueError:
			raise OptionValueError("ssh host string is improperly formatted")
		else:
			parser.values.ssh_user = u
			parser.values.ssh_host = h
			parser.values.ssh_port = p
			parser.values.use_ssh  = True
			parser.values.use_socks  = True

	# skip the formatter for the epilog....nice hack.
	def format_epilog(self, formatter):
		import textwrap
		w = ioctl_GWINSZ()[1]
		e = self.epilog.strip()
		lines = []
		[ lines.append(textwrap.fill(l,w).lstrip()) for l in e.split("%") ]
		self.epilog = "\n" + "\n".join(lines) + "\n"
		return self.epilog

	parser = OptionParser()
	ssh_opt = OptionGroup(parser, "SSH/SOCKS Options")
	debug_opt = OptionGroup(parser, "Debug Options")
	parser.add_option_group(ssh_opt)
	parser.add_option_group(debug_opt)

	# just some hack
	instancemethod = type(parser.format_epilog)
	parser.format_epilog = instancemethod(format_epilog, parser, OptionParser)

	# give some more info
	parser.epilog = epilog

	parser.add_option("-a", action="store_true",\
		help="attempt to automatically configure LAN",\
		dest="auto_config")

	parser.add_option("-w", action="store",\
		help="WAN Interface (internet)",\
		type="string", dest="wan_if")

	parser.add_option("-l", action="store",\
		help="LAN Interface (listens for xbox)",\
		type="string", dest="lan_if")

	parser.add_option("-f", action="store_true",\
		help="forward traffic from host (use with care)",\
		dest="forward_host")

	parser.add_option("-c", action="store_true",\
		help="use color for output", dest="use_color")

	parser.add_option("-q",  action="store_true",\
		help="supress output",\
		default=False, dest="quiet")

	debug_opt.add_option("--debug-supress-run",  action="store_true",\
		help="supress the running of commands",\
		default=False, dest="debug_supress_run")

	debug_opt.add_option("-v", action="count",\
		help="more v's for more output",\
		dest="verbosity")

	ssh_opt.add_option("-p", action="callback",\
		help="socks host (see below)",\
		type="string", dest="socks_host", callback=check_socks_host)

	ssh_opt.add_option("-t", action="store",\
		help="type of socks server: 4/5",\
		type="choice", dest="socks_type",\
		choices=["socks4","socks5"])

	ssh_opt.add_option("-s", action="callback",\
		help="ssh host (see below)",\
		type="string", dest="ssh_host", callback=check_ssh_host)

	opt, args = parser.parse_args()

	if opt.verbosity != None:
		opt.verbosity += 2

	if opt.quiet:
		opt.verbosity = 0

	# update the options
	for key, value in opt.__dict__.items():
		if value != None:
			#if hasattr(options, key):
			setattr(options, key, value)

# get our options from the command line
# this MUST be done here, otherwise the status messages will not reflect
# any changes to "options".  strange, but true.
if __name__ == "__main__":
	try:
		handle_arguments()
	except:
		sys.exit()

# these variables should get set automatically
magic_number  = None
lan_network   = None
xbox_host_ip  = None
wan_ip        = None
reservation_ip = None
ssh_process  = None
dnsmasq_process = None
redsocks_process = None
current_status  = None
current_term_color = None
failed = False
global_quiet = False
errors = []

# configure this host to act as a router
# please verify this is correct for you host.
# the commands variable is a list of commands
# and is simply executed one after another
# iptables is automatically added to each line
#
# NOTE:  A few of variables are available for the scripts:
#   $LAN is the interface configured for the xbox
#   $WAN is connected to the internet
#	 $SOCKS is the socks host (us, usually)
#	 $LAN_NET is the xbox's network
#   #DHCP_RANGE is the start and end IP for the xbox network
# 
#   & prefix will call a function and append results
#      function should return a list of strings to add
#
# see the run iptables script func for info

# our skeleton config for redsocks
default_redsocks_config = """
base {
	log_debug = &USE_LOG;
	log_info  = &USE_LOG;
	log = stderr;
	daemon = off;
	redirector = iptables;
}

redsocks {
	local_ip = $LAN_IP;
	local_port = $REDSOCKS_PORT;
	ip   = $SOCKS_HOST;
	port = $SOCKS_PORT;
	type = $SOCKS_TYPE;
	&USER
	&PASSWORD
}

"""

# Script to clear iptables.
# Comments are allowed in script, but not inline.
iptables_clear_script = """
--flush
--table nat --flush
--delete-chain
--table nat --delete-chain
"""

# Script to enable routing from the different interfaces.
# Comments are allowed in script, but not inline.
iptables_routing_script = """
# Turn on nat masquerade
-A POSTROUTING -t nat -o $WAN_IF -j MASQUERADE

# TCP only, to prevent udp leaks. 
# UDP isn't forwarded over the tunnel, if used
# Allow forwarding, with some security checks
#-A FORWARD -t filter -p TCP -o $WAN_IF -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
#-A FORWARD -t filter -p TCP -i $WAN_IF -m state --state ESTABLISHED,RELATED -j ACCEPT

-A FORWARD -t filter -o $WAN_IF -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
-A FORWARD -t filter -i $WAN_IF -m state --state ESTABLISHED,RELATED -j ACCEPT
"""

# Script to enable routing through redsocks 
# modified from: http://wiki.przemoc.net/tips/linux
# Comments are allowed in script, but not inline.
iptables_redsocks_script = """
# New tables for redsocks
-t nat -N REDSOCKS
-t nat -N REDSOCKS_FILTER

# Don't redirect local/loopback traffic
-t nat -I REDSOCKS_FILTER -o lo -j RETURN

# Don't redirect traffic from the socks server (ssh) over the ssh port
# becuase it causes the tunnel'd connection's traffic to be forwarded too.
&PROTECT_TUNNEL

# Please do not remove the following lines.
&HOST_FORWARDING
&PORT_RESERVATIONS

# Accept traffic from the xbox network (and nobody else)
-t nat -A REDSOCKS_FILTER -m iprange --src-range $DHCP_RANGE -j REDSOCKS
-t nat -A REDSOCKS_FILTER -j RETURN

# Don't redirect traffic from the socks server (ssh)
-t nat -I REDSOCKS -p tcp -d $SOCKS_HOST --dport $SOCKS_PORT -j RETURN

# Redirect everything else (TCP only)
-t nat -A REDSOCKS   -p tcp -j REDIRECT --to-port $REDSOCKS_PORT

# Filter traffic from host
-t nat -A OUTPUT     -p tcp -j REDSOCKS_FILTER

# Filter traffic that is routed from own host
-t nat -A PREROUTING -p tcp -j REDSOCKS_FILTER
"""

""" NETWORKING RELATED FUNCTIONS  =============================================
"""

# return the first and last hosts for the current network
def generate_dhcp_range(pool):
	net = lan_network[:lan_network.rfind(".")+1]
	host = int(xbox_host_ip[xbox_host_ip.rfind(".")+1:])
	if host + pool >= 254:
		start = 1
	else:
		start = int(host) + 1
	return "{0}{1}".format(net, start), "{0}{1}".format(net, start + pool) 

# get ip address information from the linux kernel
# from: http://code.activestate.com/recipes/
#       439094-get-the-ip-address-associated-with-a-network-inter/
def get_linux_ip_address(ifname):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	try:
		return socket.inet_ntoa(fcntl.ioctl(
			s.fileno(),
			0x8915,  # SIOCGIFADDR
			struct.pack('256s', ifname[:15])
			)[20:24])
	except IOError:
		return None

# get a list of configured interfaces.
# from: http://coderstalk.blogspot.com/2010/02/
#       create-network-interfaces-list-using.html
def get_linux_iface_list():
	import array
	import struct
	import socket
	import fcntl

	SIOCGIFCONF = 0x8912  #define SIOCGIFCONF
	BYTES = 4096          # Simply define the byte size
	sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	names = array.array('B', '\0' * BYTES)
	bytelen = struct.unpack('iL', fcntl.ioctl(sck.fileno(), \
                           SIOCGIFCONF, struct.pack('iL', BYTES, \
                           names.buffer_info()[0])))[0]
	namestr = names.tostring()
	return [namestr[i:i+32].split('\0', 1)[0] for i in range(0, bytelen, 32)]

# return a list of interfaces on the system via netstat
def get_netstat_iface_list():
	arg = ["netstat", "-i"]
	o = subprocess.Popen(arg, stdout=PIPE).communicate()[0]
	return [ line.split()[0] for line in o.split("\n")[2:-1] ]

# get a list of all interfaces on the system via /proc/net/dev
# returns all interfaces, configured or not.
def get_proc_iface_list():
	with open("/proc/net/dev") as fh:
		return [ l[:l.index(":")].lstrip() for l in fh.read().split("\n")[2:-1] ]

# used to prevent loading incorrect set of iptables rules.
def generate_magic_number():
	global magic_number
	magic_number = uuid.uuid4().hex[:6]


""" FOR THE SUPER COOL STATUS DISPLAY STUFF ===================================
"""

color_hash = {
	"reset"   : "\033[0m",
	"red"     : "\033[31m",
	"green"   : "\033[32m",
	"yellow"  : "\033[33m",
	"blue"    : "\033[34m",
	"magenta" : "\033[35m",
	"cyan"    : "\033[36m",
	"white"   : "\033[37m",
	"default" : "\033[39m",
	"gray"   : "\033[1m\033[30m",
	"bright_white"  : "\033[1m\033[37m"
}

# make pretty output
class StatusLine(object):
	finished_string = "[ Done ]"
	failed_string   = "[ Fail ]"
	wait_string     = "[ .... ]"
	r_padding = 2
	l_padding = 0
	indent_parent = set()
	indent_size = 3

	@property
	def exit_value(self):
		self.is_set = True
		return self.__exit_value

	@exit_value.setter
	def exit_value(self, value):
		if self.is_set == True:
			return
		self.__exit_value = value

	def __init__(self, msg, color=None, mode="right"):
		global current_status

		self.is_set = False
		self.is_done = False
		self.__exit_value = None

		# this means that a status is being created before another one has
		# finished.  default action is to close the other one with a wait
		# status, then continue.
		if current_status != None:
			current_status.wait()

		if options.verbosity >= 2:
			self.print_status(msg, color, mode)

		current_status = self
		self.msg = msg

	# resets indentation
	@staticmethod
	def reset():
		StatusLine.indent_parent = set()

	@staticmethod
	def print_status(msg, color, mode):
		w = ioctl_GWINSZ()[1]
		parents = len(StatusLine.indent_parent)

		color = "white"

		msg = " " * StatusLine.indent_size * parents + msg

		if StatusLine.l_padding > 0:
			msg = " " * StatusLine.l_padding + msg

		if mode == "right":
			len1 = len(StatusLine.finished_string) + StatusLine.r_padding

			if len(msg) + len1 > w:
				msg = msg[:w-len1+1] + " "
				cprint(msg, nl=False, color=color)
			else:
				s = w - len1 - len(msg)
				cprint(msg + " " * s, nl=False, color=color)		
		
		else:
			len1 = len(StatusLine.finished_string)

			if len(msg) + len1 > w:
				msg = msg[:w-len1+1] + " "

			cprint(msg, nl=False, color=color)

		# shows the status before time consuming functions	
		sys.stdout.flush()

	def fail(self, msg=None):
		global failed

		failed = True
		self.close(self.failed_string, "red", msg, "red")
		self.exit_value = False

	def finish(self, msg=None):
		self.close(self.finished_string, "white", msg, "cyan")
		self.exit_value = True

	def wait(self, msg=None):
		StatusLine.indent_parent.add(self)
		self.close(self.wait_string, "cyan", msg, "cyan")
		self.exit_value = None

	def close(self, tag, tag_color, msg=None, msg_color=None):
		if options.verbosity >= 2:
			if self.is_done == False:
				cprint(tag, color=tag_color)
	
			if msg != None:
				indent = len(StatusLine.indent_parent) + 1
				msg = " " * StatusLine.indent_size * indent + msg
				cprint(msg, color=msg_color)

		if self.is_done == True:
			try:
				StatusLine.indent_parent.remove(self)
			except:
				pass

		self.is_done = True

		# shows the status before time consuming functions	
		sys.stdout.flush()

successful_execute = []
# clever little helper to make output interesting
# check if status'd funcs completed ok
def make_status(msg):
	def wrap(func):
		def wrapped_func(*arg, **kwarg):
			global successful_execute
			status = StatusLine(msg)

			r = func(*arg, **kwarg)

			# the func may have failed.
			# check the status and return value of func
			if (r != False) and (status.exit_value != False):
				successful_execute.append(func)
				status.finish()

			return status.exit_value

		# oooo more hacks.
		wrapped_func.__original_function = func

		return wrapped_func
	return wrap

# make cleanup, etc a little more robust.
# the "child" func will not run unless the parent has been
# completed successfully.
# requires that the parent was wrapped with "make_status".
def restrict_to(parent):
	def wrap_child(child):
		def wrapped_child(*arg, **kwarg):
			if parent.__original_function in successful_execute:
				child(*arg, **kwarg)
		return wrapped_child
	return wrap_child

# only execute the func once.
# subsequent calls won't execute and will return None.
def run_once(f):
	completed = []
	def wrap():
		def wrapped_func(*arg, **kwarg):
			if f in completed:
				return None
			else:
				completed.append(f)
				return f(*arg, **kwarg)
		return wrapped_func
	return wrap

# fail the current status
def fail(text=None):
	return current_status.fail(text)

# finish the current status (0k)
def finish(text=None):
	return current_status.finish(text)

# wait on the current status
def wait(text=None):
	return current_status.wait(text)

# fail the current status, then abort the program
# the is the prefered way to abort because it makes the output pretty
def bail(text=None):
	current_status.fail(text)
	StatusLine.reset()
	cprint("")
	close_script()

# add error message to a que.  will be displayed at end of script
def error(text):
	global errors

	errors.append(str(text))

# nice abstraction of "print", includes basic color support
def cprint(text, v=2, color=None, nl=True):
	if global_quiet:
		return

	global current_term_color

	if v <= options.verbosity:
		if options.use_color:
			if current_term_color != None and color == None:
				sys.stdout.write(color_hash["reset"]+text)
			
			if color != None:
				color = color.lower()
				try:
					c = color_hash[color]
				except KeyError:
					return output(text, v, nl)

				if current_term_color != c:
					current_term_color = c
					sys.stdout.write(color_hash["reset"]+c+text)
				else:
					sys.stdout.write(text)

		else:
			sys.stdout.write(text)

		if nl == True:
			sys.stdout.write("\n")

# abstraction of printing status messages.
# if called within a function wrapped in a status, this is cause the status
# to wait.  useful for printing status messages on the status of a parent.
# use this if printing statuses in a function wrapped by make_status
def output(text, v=2, color=None, nl=True):
	if v <= options.verbosity:
		if current_status != None:
			current_status.wait()
	cprint(text, v, color, nl)

"""  SCRIPT MANGLING TIDBITS   ==============================================
"""

# class that can perform variable substitution with strings or functions
class script_transformer(object):
	def __init__(self):
		self.subs = []

	# add and precompile a regex for subs
	def add(self, string, value):
		regex = re.compile("\$%s" % string, re.MULTILINE)
		self.subs.append((regex, value))

	# funcs passed as op are able to be matched by the func name	
	def substitute(self, text, operators=[]):
		op = {}

		# first, search the text with func in operators
		for f in operators:
			regex = re.compile("\&%s" % f.__name__.upper(), re.MULTILINE)
			if regex.search(text):
				s = f()
				if s != None:
					if type(s) == type([]):
						text = regex.sub("\n".join(s), text)
					elif type(s) == type(""):
						text = regex.sub(s, text)
				else:
						text = regex.sub("", text)
					
		# then, search using the subs already added
		for regex, value in self.subs:
			text = regex.sub(str(value), text)

		return text

# this is a digital band aid...
g_st = None
@make_status("Populating internal variables for parser")
def initialize_parser():
	global g_st

	g_st = script_transformer()	
	g_st.add("LAN_IF", options.lan_if)
	g_st.add("WAN_IF", options.wan_if)
	g_st.add("LAN_IP", xbox_host_ip)
	g_st.add("LAN_NET", lan_network)
	g_st.add("DHCP_RANGE", "-".join(generate_dhcp_range(options.dhcp_pool)))
	g_st.add("RESERVATION", reservation_ip)
	g_st.add("SSH_HOST", get_ip_address(options.ssh_host))
	g_st.add("SOCKS_HOST", get_ip_address(options.socks_host))
	g_st.add("SOCKS_PORT", options.socks_port)
	g_st.add("SOCKS_TYPE", options.socks_type)
	g_st.add("REDSOCKS_PORT", options.redsocks_port)

"""  ALL THE FUNCTIONS WRAPPED BY MAKE_STATUS AND THEIR HELPERS ===============
"""

@make_status("Enabling Linux kernel routing")
def enable_linux_routing():
	f = "/proc/sys/net/ipv4/ip_forward"
	if check_proc_file(f) != "1":
		with open(f, "w") as fh:
			fh.write("1")

@make_status("Enabling Linux kernel syncookies")
def enable_linux_syncookies():
	f = "/proc/sys/net/ipv4/tcp_syncookies"
	if check_proc_file(f) != "1":
		with open(f, "w") as fh:
			fh.write("1")

@restrict_to(enable_linux_routing)
@make_status("Disabling Linux kernel routing")
def disable_linux_routing():
	try:
		with open("/proc/sys/net/ipv4/ip_forward", "w") as fh:
			fh.write("0")
	except IOError as e:
		fail("Cannot write to proc filesystem.  (are you root?)")
	except:
		raise

@restrict_to(enable_linux_syncookies)
@make_status("Disabling Linux kernel syncookies")
def disable_linux_syncookies():
	try:
		with open("/proc/sys/net/ipv4/tcp_syncookies", "w") as fh:
			fh.write("0")
	except IOError as e:
		fail("Cannot write to proc filesystem.  (are you root?)")
	except:
		raise

@make_status("Clearing iptables information")
def clear_iptables():
	run_iptables_script(iptables_clear_script)

@make_status("Configuring iptables")
def configure_iptables_routing():
	run_iptables_script(iptables_routing_script)

def run_iptables_script(script):
	# add lines for optional port reservations
	# connections to reserved ports will not be forwarded through redsocks
	def port_reservations():
		if options.reserve_ports != []:
			s="-t nat -A REDSOCKS_FILTER -p tcp -d {0} --dport {1} -j RETURN"
			return [ s.format(xbox_host_ip, port) \
				for port in options.reserve_ports ]
		else:
			return None 

	# handle host forwarding
	def host_forwarding():
		#if options.forward_host:
		#	s="-t nat -A REDSOCKS_FILTER -s {0} -j REDSOCKS"
		#	return s.format(wan_ip)
		pass

	# protect the ssh client from its packets being tunneled thru itself
	def protect_tunnel():
		if options.use_ssh and options.forward_host:
			ssh_host_ip = get_ip_address(options.ssh_host)

			s="-t nat -A REDSOCKS_FILTER -p tcp -d {0} --dport {1} -j RETURN"
			return s.format(ssh_host_ip, options.ssh_port)

	op = (port_reservations, host_forwarding, protect_tunnel)
	modified_script = g_st.substitute(script, op)

	#for line in modified_script.split("\n")[1:-1]:
	for line in modified_script.strip().split("\n"):
		line = line.strip()
		if line == "": continue
		if line[0] != "#":
			arg = ["iptables"]
			arg.extend(line.split())
			run_command(arg)

@make_status("Configuring iptables for redsocks")
def configure_iptables_redsocks():
	run_iptables_script(iptables_redsocks_script)

# redsocks doesn't take command line arguments.
# generate a file based on the current configuration.
@make_status("Configuring redsocks")
def configure_redsocks():
	def use_log():
		if options.verbosity >= 4:
			return "on"
		else:
			return "off"

	def user():
		try:
			
			return options.socks_user + ";\n"
		except (AttributeError, TypeError):
			pass

	def password():
		try:
			return options.socks_password + ";\n"
		except (AttributeError, TypeError):
			pass

	op = (use_log, user, password)
	config = g_st.substitute(default_redsocks_config, op)

	with open("redsocks.conf", "w") as fh:
		fh.write(config)

def check_proc_file(file):
	with open(file) as fh:
		return fh.readline().strip()

"""   NETWORKING STATUS-FUNCTIONS   =========================================
"""

# make sure the system is configured properly
# test_interfaces makes sure there are at least two interfaces
# verify_iface makes sure the chosen iface is properly configured
# configure_iface will attempt set set the system up so it works
@make_status("Getting the system interfaces ready")
def ready_interfaces():
	ifaces = get_proc_iface_list()

	# make sure our wan interface is configured with valid ip address
	if options.wan_if not in ifaces:
		bail("WAN interface %s is not found." % options.wan_if)

	# test to make sure there are at least two interfaces to configure.
	try:
		ifaces.remove("lo")
	except ValueError:
		pass

	if len(ifaces) < 2:
		bail("Less than two interfaces available, cannot continue.")

	if not verify_lan_if():
		if options.auto_config:
			configure_iface()
		else:
			fail("Cannot verify interface {0}.".format(options.lan_if))
			output("Check configuration, or try enabling auto-config.")
			bail()

	if not verify_wan_if():
		fail("Cannot verify interface {0}.".format(options.wan_if))
		output("Check configuration.")
		bail()

	current_status.finish()

	i = " " * StatusLine.indent_size * (len(StatusLine.indent_parent) + 1)

	output("{0}WAN connection interface:       {1}".format(i,options.wan_if), 3)
	output("{0}Listening on interface:         {1}".format(i,options.lan_if), 3)
	output("{0}IP address of host:             {1}".format(i,xbox_host_ip), 3)
	#output("{0}Network address:                {1}".format(i,lan_network), 3)

def verify_wan_if():
	global wan_ip

	wan_ip = get_linux_ip_address(options.wan_if)

	return True

# check a few websites to guess if the internet connection works, or not
# http://bytes.com/topic/python/answers/821438-testing-internet-connection
@make_status("Checking for Internet connectivity")
def check_internet():
	import socket, struct

	def check_host(host, port, timeout=1):
		ret=False
		try:
			sock=socket.socket()
			timeval=struct.pack("2I", timeout, 0)
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeval)
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, timeval)
			sock.connect((host, port))
			sock.shutdown(socket.SHUT_RDWR)
			ret=True
		except (socket.error, socket.herror, socket.gaierror, socket.timeout):
			ret=False

		try:
			sock.close()
		except:
			pass

		return ret

	hosts=["www.google.com", "www.yahoo.com", "www.bing.com", "www.speedtest.net"]

	for h in hosts:
		if check_host(h, 80):
			return True

	return False

# verify that we can run a dhcp server on this interface
# the interface exists
# the interface should be up
# the interface should have an ip address
# the interface is on an unique network
# the ip address should be non-routable (192.168.x.x)
#@make_status("Verifying interface {0}".format(options.lan_if))
def verify_lan_if():
	ip_re = re.compile("(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")

	global xbox_host_ip, lan_network

	# make it easier to type.
	lan_if = options.lan_if

	# tests that iface esists and is up
	if lan_if not in get_proc_iface_list():
		error("Cannot find the specified interface {0}".format(lan_if))
		bail("Cannot find interface {0}".format(lan_if))

	ip = get_linux_ip_address(lan_if)

	# valid ip?
	if ip == None:
		fail("Interface {0} does not have a valid IP address".format(lan_if))
		return False
		
	if ip_re.match(ip) == None:
		fail("Interface {0} does not have a valid IP address".format(lan_if))
		return False

	# unique network?
	ifaces = get_linux_iface_list()
	ifaces.remove(lan_if)

	networks = []
	for interface in ifaces:
		ip2 = get_linux_ip_address(interface)
		networks.append(ip2[:ip2.rfind(".")] + ".0")

	network = ip[:ip.rfind(".")] + ".0"
	if network in networks:
		fail("Interface {0} is configured to another network.".format(lan_if))
		return False
 
	# does it [not] route?
	if ip[:8] != "192.168.":
		fail("Please use network address 192.168.x.x.".format(lan_if))
		return False

	xbox_host_ip = ip
	lan_network = network

	return True

# configure the interfaces to something sensible if desired
# network detection is very simplistic and might not work with complex networks
# ok for most cases
@make_status("Attempting to auto-configure {0}".format(options.lan_if))
def configure_iface():
	global xbox_host_ip, lan_network

	# global quiet could be used here
	# don't fix it if it isn't broken
	#if verify_lan_if():
	#	finish("{0} already properly configured.".format(options.lan_if))
	#	return True

	# find a network that isn't being used	
	ifaces = get_linux_iface_list()
	try:
		ifaces.remove(options.lan_if)
	except ValueError:
		pass
	
	networks = []
	ips      = []
	for iface in ifaces:
		ip = get_linux_ip_address(iface)
		ips.append(ip)
		networks.append(ip[:ip.rfind(".")] + ".0")

	# find a network address not used on the system yet
	free_network = None
	for x in range(0,255):
		n = "192.168.{0}.0".format(x)
		if n not in networks:
			free_network = n
			break

	if free_network == None:
		fail("Cannot auto-configure interfaces.")
		return False

	lan_network = free_network
	xbox_host_ip = free_network[:free_network.rfind(".")] + ".1"

	# configure the interface
	arg = [ifconfig_bin, options.lan_if, xbox_host_ip]
	run_command(arg)

# test if configuration exists, and is properly formatted
# if not, add option to generate one
def test_redsocks_conf():
	pass

"""   PROCESS STARTING STATUS-FUINCTIONS   ==================================
"""

@make_status("Starting SSH as socks5 proxy")
def start_ssh():
	global ssh_process

	if test_link_clear() == False:
		fail("cannot start ssh because local port is in use")
		return

	arg = [ssh_bin, "-N"]

	if options.verbosity == 0:
		arg.append("-q")

	arg.extend(options.ssh_opt.split())
	arg.extend(("-D", str(options.socks_port)))
	
	#if socks_port:
	#	arg.append("-D {0}".format(socks_port))
	#else:
	#	for port in forward_ports:
	#		arg.append("-L {0}:{1}:{0}".format(port, ssh_host))

	if options.ssh_port:
		arg.extend(("-p", str(options.ssh_port)))

	arg.append("{0}@{1}".format(options.ssh_user, options.ssh_host))

	ssh_process = start_process(arg, quiet=False)
	if ssh_process == None:
		bail("Error has occured with ssh.")

	current_status.finish()

	i = " " * StatusLine.indent_size * (len(StatusLine.indent_parent) + 1)

	output("{0}SSH tunnel to                   {1}".format(i,options.ssh_host), 3)
	output("{0}On port                         {1}".format(i,options.ssh_port), 3)
	output("{0}Connected as user:              {1}".format(i,options.ssh_user), 3)
	#output("{0}Forwarding ports:        {1}".format(i,str(forward_ports).strip("[]")), 3)
	output("{0}Listening port:                 {1}".format(i,options.socks_port), 3)

@make_status("Starting redsocks")
def start_redsocks():
	global redsocks_process

	arg = [redsocks_bin, "-c", "redsocks.conf"]

	redsocks_process = start_process(arg)
	current_status.finish()

	i = " " * StatusLine.indent_size * (len(StatusLine.indent_parent) + 1)
	output("{0}Listening on port:              {1}".format(i,options.redsocks_port), 3)
	output("{0}Forwarding to host:             {1}".format(i,options.socks_host), 3)
	output("{0}On port:                        {1}".format(i,options.socks_port), 3)
	if options.socks_user:
		output("{0}As user:                        {1}".format(i,options.socks_user), 3)

# configure dnsmasq some, then start it	
@make_status("Starting DHCP server (dnsmasq)")
def start_dnsmasq():
	global reservation_ip
	global dnsmasq_process
	
	arg = [dnsmasq_bin, "-k", "--interface={0}".format(options.lan_if)]

	first, last  = generate_dhcp_range(options.dhcp_pool)
	range = "{0},{1},{2}".format(first, last, options.dhcp_lease) 

	arg.append("--dhcp-range={0}".format(range))
	
	# if we have the MAC of the xbox, then set a special IP to forward the ports
	# the reservation will be the last host of the range
	# if not mac, then make the reservation the first host
	if options.xbox_mac != None:
		reservation_ip = last
		arg.append("--dhcp-host={0},{1}".format(options.xbox_mac, reservation_ip))
	else:
		reservation_ip = first

	dnsmasq_process = start_process(arg)

	current_status.finish()

	i = " " * StatusLine.indent_size * (len(StatusLine.indent_parent) + 1)
	output("{0}Started on interface            {1}".format(i,options.lan_if), 3)

	if options.xbox_mac != None:
		output("{0}Reservation for {0}:            {2}".format(i,options.xbox_mac, reservation_ip), 3)
	else:
		output("{0}DMZ is set to 1st IP:           {1}".format(i,reservation_ip), 3)


# run a command, wait for it to finish
def run_command(arg):
	output("running command: %s" % " ".join(arg), 4)

	if options.debug_supress_run:
		return True

	p = None

	try:
		p = subprocess.Popen(arg, stdout=PIPE, stderr=STDOUT, bufsize=1024)
		if options.verbosity >= 3:
			output(p.communicate()[0], nl=False)
	except OSError as e:
		fail("failed command: {0}".format(" ".join(arg)))
		bail("(are you root?)")	

	p.wait()
	
	if p.returncode != 0:
		fail("failed command: {0}".format(" ".join(arg)))
		fail("(are you root?)")	
		bail()
		return False

	return True

# run a command, but keep the process running
def start_process(arg, quiet=True):
	try:
		output("starting process: %s" % " ".join(arg), 4)

		if options.debug_supress_run:
			return True

		if options.verbosity >= 4:
			p = subprocess.Popen(arg)
		else:
			p = subprocess.Popen(arg, stdout=PIPE, stderr=PIPE, bufsize=1024)
	except OSError as oserror:
		fail("failed command: %s" % " ".join(arg))
		fail("are you root?  are you in the right directory?")
		error("cannot find file: %s" % str(arg[0]))
	except:
		fail("failed command: %s" % " ".join(arg))
		raise

	pretty_name = arg[0][arg[0].rfind("/")+1:]

	# get some output:
	#if not quiet:
	#	output(p.communicate()[1].strip())

	#time.sleep(1)

	if p == None:
		fail("{0} has failed to start.".format(pretty_name))
		bail()

	retcode = p.poll()
	if p.poll() != None:
		try:
			[ error(x) for x in p.stderr.read().strip().split("\n") ]
		except:
			pass

		fail("{0} has failed to start.".format(pretty_name))
		bail()

	return p

def test_link_clear():
	pids = set()
	#[ pids.add(test_port(port)) for port in forward_ports ]
	
	pids.add(test_port(options.socks_port))	

	pids.discard(False)
	
	if len(pids) == 0:
		return True
	else:
		pids_pretty = str(list(pids)).strip("[]")
		output("Cannot establish link.")
		output("Process(es) {0} are using some of the ports.".format(pids_pretty))
		return False
	
# Test if a process is listening on a port.
# Return False if open, otherwise return pid of a process using the port.
def test_port(port):
	arg = ["lsof", "-i", "tcp:{0}".format(port)]
	o = subprocess.Popen(arg, stdout=PIPE).communicate()[0]

	if o == None:
		return False

	pids = set()
	[ pids.add(line.split()[1]) for line in o.split("\n")[2:-1] \
		if line.find("(LISTEN)") > 0 ]

	if len(pids) == 0:
		return False
	else:
		# laziness, just return the first pid
		return int(pids.pop())

"""  IPTABLES STATUS-FUNCTIONS ==============================================
"""

def check_iptables():
	regex = re.compile("iptable_nat|iptable_filter", re.MULTILINE)
	fh = open("/proc/modules")
	mod = []
	[ mod.append(x) for x in fh.readlines() if regex.match(x) ]

	if len(mod) != 2:
		if options.auto_config:
			if run_command("modprobe ip_tables".split()):
				return
			else:
				fail("cannot load ip_tables kernel modules")
				bail("please check your kernel for ip_tables support")
				
		else:
			fail("iptables kernel modules are not loaded.")
			bail("make sure that iptables_filter and iptables_nat are loaded.")

@make_status("Saving existing iptables configuration")
def save_iptables():
	save = "iptables-{0}.save".format(magic_number)
	arg = [shell_bin, "-c"]
	arg.append("iptables-save > iptables-{0}.save".format(magic_number))
	try:
		run_command(arg)
	except OSError:
		raise
		current_status.fail()
		output("   Unable to save iptables: {0}".format(save))

	current_status.finish()

@restrict_to(save_iptables)
@make_status("Restoring iptables configuration")
def restore_iptables():
	save = "iptables-{0}.save".format(magic_number)
	arg = [shell_bin, "-c"]
	arg.append("cat {0} | iptables-restore".format(save))
	try:
		run_command(arg)
	except OSError:
		current_status.fail("Unable to restore iptables: {0}".format(save))
	pass

	try:
		os.remove(save)
	except OSError:
		pass

""" MISC  ===================================================================
"""
	
def get_socks5_password():
	import cmd

	password = ""

	def precmd(self, line):
		password = line
		return line

	def postcmd(self, stop, line):
		return True

	# patch some stuff here
	c = cmd.Cmd()
	instancemethod = type(c.precmd)
	c.precmd = instancemethod(precmd, c, cmd.Cmd)
	c.postcmd = instancemethod(postcmd, c, cmd.Cmd)

	output("Enter password for socks 5 proxy, or press enter for none.")
	c.prompt = "[none] "
	c.cmdloop()

	if password != "":
		options.socks_password = password

def verify_inputs():

	mac_re = re.compile("^(([a-f0-9]){2}:){5}([a-f0-9]){2}$", re.IGNORECASE)

	if options.xbox_mac != None and not mac_re.match(options.xbox_mac):
		fail("Xbox MAC address not configured properly.")

	if options.socks_user:
		if options.socks_type == "socks5":
			get_socks5_password()
		else:
			output("Username is set for socks 4 proxy.")
			output("Passwords are not supported for socks 4 proxies")

#@make_status("Closing processes")
def kill_processes():
	for p in [redsocks_process, ssh_process, dnsmasq_process]:
		try:
			p.kill()
		except:
			pass

# shut down everything [hopefully] gracefully	
# BEWARE:  anything that calls "bail()" from here will cause a inf. loop!
@make_status("Closing connections and processes")
def close_script(quiet=False):
	global global_quiet

	StatusLine.reset()

	kill_processes()

	try:
		restore_iptables()
		disable_linux_routing()
		disable_linux_syncookies()
	except:
		raise

	if quiet:
		global_quiet = False

	finish()

	if failed == True:
		if errors != []:
			output("\nErrors encountered:")
			for line in errors:
				if line != "":	output(line)
		else:
			output("")

		cprint("There were errors while running the script.", color="red")
	else:
		cprint("\nGoodbye!", 1)

	sys.exit()

@make_status("Initializing iptables")
def initialize_iptables():
	check_iptables()
	save_iptables()
	clear_iptables()

@make_status("Configuring system for NAT")
def configure_nat():
	enable_linux_routing()
	enable_linux_syncookies()
	configure_iptables_routing()	

@make_status("Configuring system for socks proxy")
def configure_system_socks():
	configure_iptables_redsocks()
	configure_redsocks()
	start_redsocks()

@make_status("Initializing internal parameters")
def initialize():
	generate_magic_number()
	verify_inputs()

@make_status("Configuring the system, starting processes, etc")
def configure_system():
	initialize()

	# ready_interfaces() should be done before anything network related.
	# you've been warned.
	ready_interfaces()
	initialize_parser()
	initialize_iptables()

	if options.use_socks:
		configure_system_socks()

	if options.use_ssh:
		start_ssh()

	if not options.use_ssh:
		output("")
		
	configure_nat()

	# this should be last.  prevents packets from leaking past ssh/socks
	# if the system is still in the process of starting up...
	start_dnsmasq()

	# wait for everything to settle
	time.sleep(1)

	cprint("")
	cprint("Ready to accept connections on {0}.".format(options.lan_if), 1, "green")
	cprint("Press CTRL + C to close the connection and quit.", 1, "blue")
	cprint("", nl=False, color="reset")

def run_processes():
	# return True if no longer running
	def check_process(p):
		try:
			r = p[0].poll()
		except AttributeError:
			return False

		if r != None:
			cprint("%s is DOWN." % p[2], color="red")
			[ error(x) for x in p[0].stderr.read().strip().split("\n") if x != ""]
			return True

		return False

	def restart_process(p):
		cprint("attempting to recover %s..." % p[2], color="red")
		p[1]()

	try:
		down = 3

		while 1:
			time.sleep(1)
	
			for p in ((dnsmasq_process, start_dnsmasq, "dnsmasq"), \
						(redsocks_process, start_redsocks, "redsocks"), \
						(ssh_process, start_ssh, "ssh")):

				if check_process(p):
					if down == 0:
						bail("Too many failures of the daemons.")
					else:
						restart_process(p)
						down -= 1

	except KeyboardInterrupt:
		cprint("\n")
		close_script()

# finally, run the thing!
if __name__ == "__main__":
	import traceback
	
	try:
		configure_system()
		run_processes()
	except KeyboardInterrupt:
		bail("Caught KILL signal, CTRL + C")
	except SystemExit:
		pass
	except:
		if options.verbosity > 2:
			traceback.print_exc(file=sys.stdout)
		bail("Error in script (use -v for more info)")
