#!/usr/bin/perl -w
############################## check_wifi_stats ##############
# Version : 1.2.0
# Date : Oct 25 2019
# Author  : Andrew Radke ( andrew at openspacesinternet.com.au )
# Help : http://nagios.manubulon.com
# Licence : GPL - http://www.fsf.org/licenses/gpl.txt
# Contrib : J. Jungmann, S. Probst, R. Leroy, M. Berger, Patrick Proy
#################################################################
#
# Help : ./check_wifi_stats.pl -h
#

################### NOTE #####################
# For SNMPv3 to work with Mikrotiks /usr/share/perl5/Net/SNMP.pm must be patched.
# Inside sub _discovery_synchronization_cb change:
#
# @@ -2618,7 +2618,7 @@
#     # assume that the synchronization has failed.
#  
#     if (($this->{_security}->discovered()) &&
# -       ($this->{_error} =~ /usmStatsNotInTimeWindows/))
# +       ((!$this->{_error}) || ($this->{_error} =~ /usmStatsNotInTimeWindows/)))
#     {
#        $this->_error_clear();
#        DEBUG_INFO('discovery and synchronization complete');

use strict;
use Net::SNMP;
use Getopt::Long;

# Nagios specific

use lib "/usr/lib/nagios/plugins";
use utils qw(%ERRORS $TIMEOUT);

# Mimosa
#   signal strength (x10):	1.3.6.1.4.1.43356.2.1.2.6.6.0
#   for bandwidth add all the streams together to get physical rate
#   bandwidth TX phy:		1.3.6.1.4.1.43356.2.1.2.6.2.1.2. [1-4] for B5(c) or [1-2] for B5lite
#   bandwidth RX phy:		1.3.6.1.4.1.43356.2.1.2.6.2.1.2. [1-4] for B5(c) or [1-2] for B5lite

# Mikrotik
#  Wireless registration table. It is indexed by remote mac-address and local interface index
#   remote mac-addr:	1.3.6.1.4.1.14988.1.1.1.2.1.1.108.59.107.99.57.223.7
#                                                     ^^^^^^^^^^^^^^^^^^^^ MAC address
#   signal:		1.3.6.1.4.1.14988.1.1.1.2.1.3.108.59.107.99.57.223.7
#   bandwidth tx:	1.3.6.1.4.1.14988.1.1.1.2.1.8.108.59.107.99.57.223.7
#   bandwidth rx:	1.3.6.1.4.1.14988.1.1.1.2.1.9.108.59.107.99.57.223.7

# SNMP Datas
my $Mikrotik_table	= '1.3.6.1.4.1.14988.1.1.1.2.1';
my $Mikrotik_60g_table	= '1.3.6.1.4.1.14988.1.1.1.8.1';
my $Mimosa_table	= '1.3.6.1.4.1.43356.2.1.2.6';
my $airFiber_table	= '1.3.6.1.4.1.41112.1.10.1.4.1';

my $reg_table = undef;
my $descr_table = '1.3.6.1.2.1.2.2.1.2';
my $oper_table = '1.3.6.1.2.1.2.2.1.8.';
my $admin_table = '1.3.6.1.2.1.2.2.1.7.';

my %status=(0=>'OK',1=>'WARNING',2=>'CRITICAL',3=>'UNKNOWN');

# Globals

my $Version='1.2.0';

# Standard options
my $o_host= 		undef; 		# hostname
my $o_port= 		161; 		# port
my $o_protocol=		1;		# SNMP protocol version
my $o_timeout=		5; 		# Timeout (Default 5)
my $o_help=		undef; 		# wan't some help ?
my $o_verb=		undef;		# verbose mode
my $o_version=		undef;		# print version

# SNMP Message size parameter (Makina Corpus contrib)
my $o_octetlength=	undef;

# Interface and radio type options
my $o_descr= 		undef; 		# description filter
my $o_admin=		undef;		# admin status instead of oper
my $o_noreg=		undef;		# Do not use Regexp for name
my $o_short=		undef;		# set maximum of n chars to be displayed
my $o_type=		'Mikrotik';	# radio type

# Performance data options 
my $o_perf=     	undef;		# Output performance data
my $o_warn=		undef;		# warning options
my $o_crit=		undef;  	# critical options
my $o_ratewarn=		undef;  	# warning options
my $o_ratecrit=		undef;  	# critical options
my $o_txratewarn=	undef;  	# warning options
my $o_txratecrit=	undef;  	# critical options
my $o_rxratewarn=	undef;  	# warning options
my $o_rxratecrit=	undef;  	# critical options

# Login options specific
my $o_community = 	'public'; 	# community
my $o_seclevel =	'authPriv';	# SNMPv3 security level
my $o_secname =		undef;		# SNMPv3 username
my $o_authproto =	'SHA';		# SNMPv3 auth protocol
my $o_authpasswd =	undef;		# SNMPv3 auth password
my $o_privproto =	'AES';		# SNMPv3 privacy protocol
my $o_privpasswd =	undef;		# SNMPv3 provacy password


# Readable names for counters (M. Berger contrib)
my @countername = ( "in=" , "out=" , "errors-in=" , "errors-out=" , "discard-in=" , "discard-out=" );

my $mimosa_chains = 4;

# functions

sub p_version { print "check_wifi_stats version : $Version\n"; }

sub print_usage {
    print "Usage: $0 [-v] -H <host> [-p <port>] [-C <community>] [-P <snmp_version>] [-L seclevel] [-U secname] [-a authproto] [-A authpasswd] [-x privproto] [-X privpasswd] -n <name in desc_oid> [--admin] [-r] [-f] [-T <radio_type>] -w <warn levels> -c <crit levels> [--rate_warning=<Mbps> --rate_crritical=<Mbps>] [--txrate_warning=<Mbps> --txrate_crritical=<Mbps>] [--rxrate_warning=<Mbps> --rxrate_crritical=<Mbps>] [-o <octet_length>] [-t <timeout>] [-s] [-V]\n";
}

sub isnnum { # Return true if arg is not a number
  my $num = shift;
  if ( $num =~ /^(\d+\.?\d*)|(^\.\d+)$/ ) { return 0 ;}
  return 1;
}

sub help {
   print "\nSNMP Network Interface Monitor for Nagios version ",$Version,"\n";
   print "GPL licence, (c)2004-2007 Patrick Proy\n\n";
   print_usage();
   print <<EOT;
-v, --verbose
   print extra debugging information (including interface list on the system)
-h, --help
   print this help message
-H, --hostname=HOST
   name or IP address of host to check
-P, --port=PORT
   SNMP port, default: 161
-C, --community=STRING
   Optional community string for SNMP communication, default: "public"
-P, --protocol=[1|2c|3]
   SNMP protocol version, default: 1
-L, --seclevel=[noAuthNoPriv|authNoPriv|authPriv]
   SNMPv3 securityLevel, default: "authPriv"
-a, --authproto=[MD5|SHA]
   SNMPv3 auth proto, default: "SHA"
-x, --privproto=[DES|AES]
   SNMPv3 priv proto, default: "DES"
-U, --secname=USERNAME
   SNMPv3 username
-A, --authpasswd=PASSWORD
   SNMPv3 authentication password
-X, --privpasswd=PASSWORD
   SNMPv3 privacy password
-n, --name=NAME
   Name in description OID (eth0, ppp0 ...).
   This is treated as a regexp : -n eth will match eth0,eth1,...
   Test it before, because there are known bugs (ex : trailling /)
-r, --noregexp
   Do not use regexp to match NAME in description OID
--admin
   Use administrative status instead of operational
-o, --octetlength=INTEGER
  max-size of the SNMP message, usefull in case of Too Long responses.
  Be carefull with network filters. Range 484 - 65535, default is
  usually 1472,1452,1460 or 1440.     
-f, --perfparse
   Perfparse compatible output (no output when interface is down).
-w, --warning=dBm
   dBm level below which a warning is given
-c, --critical=dBm
   dBm level below which a critical is given
--rate_warning=Mbps or --txrate_warning=Mbps --rxrate_warning=Mbps
   Mbps below which a warning is given (0 for no warning)
--rate_critical=Mbps or --txrate_critical=Mbps --rxrate_critical=Mbps
   Mbps below which a critical is given (0 for no warning)
-s, --short=int
   Make the output shorter : only the first <n> chars of the interface(s)
   If the number is negative, then get the <n> LAST caracters.
-t, --timeout=INTEGER
   timeout for SNMP in seconds, default: 5
-T, --type=TYPE
   Type of radio to check. Currently support Mikrotik, Mikrotik_60g, airFiber, Mimosa and MimosaLite.
   default: Mikrotik
-V, --version
   prints version number
Note : when multiple interface are selected with regexp, 
       all be must be up (or down with -i) to get an OK result.
EOT
}

# For verbose output
sub verb { my $t=shift; print $t,"\n" if defined($o_verb) ; }

sub check_options {
    Getopt::Long::Configure ("bundling");
	GetOptions(
   	'v'	=> \$o_verb,		'verbose'	=> \$o_verb,
        'h'     => \$o_help,    	'help'        	=> \$o_help,
        'H:s'   => \$o_host,		'hostname:s'	=> \$o_host,
        'p:i'   => \$o_port,   		'port:i'	=> \$o_port,
        'C:s'   => \$o_community,	'community:s'	=> \$o_community,
        'P:s'   => \$o_protocol,	'protocol:s'	=> \$o_protocol,
        'L:s'   => \$o_seclevel,	'seclevel:s'	=> \$o_seclevel,
        'U:s'   => \$o_secname,		'secname:s'	=> \$o_secname,
        'a:s'   => \$o_authproto,	'authproto:s'	=> \$o_authproto,
        'A:s'   => \$o_authpasswd,	'authpasswd:s'	=> \$o_authpasswd,
        'x:s'   => \$o_privproto,	'privproto:s'	=> \$o_privproto,
        'X:s'   => \$o_privpasswd,	'privpasswd:s'	=> \$o_privpasswd,

	'n:s'   => \$o_descr,           'name:s'        => \$o_descr,
        't:i'   => \$o_timeout,    	'timeout:i'	=> \$o_timeout,
					'admin'		=> \$o_admin,
	'T:s'	=> \$o_type,		'type:s'	=> \$o_type,
	'r'	=> \$o_noreg,		'noregexp'	=> \$o_noreg,
	'V'	=> \$o_version,		'version'	=> \$o_version,
        'f'     => \$o_perf,            'perfparse'     => \$o_perf,
        'w:i'   => \$o_warn,       	'warning:i'   	=> \$o_warn,
        'c:i'   => \$o_crit,      	'critical:i'   	=> \$o_crit,
					'rate_warning:i'   	=> \$o_ratewarn,
					'rate_critical:i'   	=> \$o_ratecrit,
					'txrate_warning:i'   	=> \$o_txratewarn,
					'txrate_critical:i'   	=> \$o_txratecrit,
					'rxrate_warning:i'   	=> \$o_rxratewarn,
					'rxrate_critical:i'   	=> \$o_rxratecrit,
        's:i'   => \$o_short,      	'short:i'   	=> \$o_short,
	'o:i'   => \$o_octetlength,    	'octetlength:i' => \$o_octetlength,
    );
    if (defined ($o_help) ) { help(); exit $ERRORS{"UNKNOWN"}};
    if (defined ($o_version) ) { p_version(); exit $ERRORS{"UNKNOWN"}};

    if ( ! defined($o_descr) || ! defined($o_host) ) # check host and filter 
      { print_usage(); exit $ERRORS{"UNKNOWN"}; }

    if ( $o_protocol ne 1 && $o_protocol ne '2c' && $o_protocol ne 3 )
      { print "SNMP protocol version must be 1, 2c or 3.\n"; print_usage(); exit $ERRORS{"UNKNOWN"}; }

    if ($o_protocol eq 3 ) {
      if ( !defined($o_secname) )
	{ print "SNMPv3 requires secname (username) to be specified.\n"; print_usage(); exit $ERRORS{"UNKNOWN"}; }
      if ($o_seclevel eq 'authPriv') {
        if ( !defined($o_authpasswd) || !defined($o_authproto) || !defined($o_privpasswd) || !defined($o_privproto) )
          { print "SNMPv3 security level 'authPriv; requires authpasswd, authproto, privpasswd and privproto to ALL be specified.\n"; print_usage(); exit $ERRORS{"UNKNOWN"}}
      } elsif ($o_seclevel eq 'authNoPriv') {
        if ( !defined($o_authpasswd) || !defined($o_authproto) || !defined($o_privpasswd) || !defined($o_privproto) )
          { print "SNMPv3 security level 'authNoPriv; requires authpasswd and authproto to BOTH be specified.\n"; print_usage(); exit $ERRORS{"UNKNOWN"}}
      }
    }

    if (defined($o_timeout) && (isnnum($o_timeout) || ($o_timeout < 2) || ($o_timeout > 60))) 
      { print "Timeout must be >1 and <60 !\n"; print_usage(); exit $ERRORS{"UNKNOWN"}}

    #### octet length checks
    if (defined ($o_octetlength) && (isnnum($o_octetlength) || $o_octetlength > 65535 || $o_octetlength < 484 )) {
		print "octet lenght must be < 65535 and > 484\n";print_usage(); exit $ERRORS{"UNKNOWN"};
    }	
    if (lc($o_type) eq 'mikrotik') {
      $reg_table = $Mikrotik_table . ".1";
    } elsif (lc($o_type) eq 'mikrotik_60g') {
      $reg_table = $Mikrotik_60g_table;
    } elsif (lc($o_type) eq 'airfiber') {
      $reg_table = $airFiber_table . ".1";
    } elsif (lc($o_type) eq 'mimosa') {
      $reg_table = $Mimosa_table;
    } elsif ($o_type eq 'MimosaLite') {
      $reg_table = $Mimosa_table;
      $o_type = 'Mimosa';
      $mimosa_chains = 2;
    } else {
      print "Unknown radio type: '$o_type'\n";print_usage(); exit $ERRORS{"UNKNOWN"};
    }
    $o_type = lc($o_type);
}
    
########## MAIN #######

check_options();

# Check gobal timeout if snmp screws up
if (defined($TIMEOUT)) {
  verb("Alarm at $TIMEOUT + 5");
  alarm($TIMEOUT+5);
} else {
  verb("no timeout defined : $o_timeout + 10");
  alarm ($o_timeout+10);
}

$SIG{'ALRM'} = sub {
 print "No answer from host\n";
 exit $ERRORS{"UNKNOWN"};
};

# Connect to host
my ($session,$error);
if ($o_protocol eq 3) {
  # SNMPv3 login
  if ($o_seclevel eq 'authPriv') {
    verb("SNMPv3 AuthPriv login: $o_privproto, $o_authproto, $o_secname");
    ($session, $error) = Net::SNMP->session(
	-hostname   	=> $o_host,
	-port      	=> $o_port,
	-version	=> '3',
	-username	=> $o_secname,
	-authpassword	=> $o_authpasswd,
	-authprotocol	=> $o_authproto,
	-privpassword	=> $o_privpasswd,
	-privprotocol	=> $o_privproto,
	-timeout	=> $o_timeout
    );
  } elsif ($o_seclevel eq 'authNoPriv') {
    verb("SNMPv3 AuthNoPriv login: $o_authproto, $o_secname");
    ($session, $error) = Net::SNMP->session(
      -hostname   	=> $o_host,
      -port      	=> $o_port,
      -version		=> '3',
      -username		=> $o_secname,
      -authpassword	=> $o_authpasswd,
      -authprotocol	=> $o_authproto,
      -timeout          => $o_timeout
    );
  } else {
    verb("SNMPv3 noAuthNoPriv login: $o_secname");
    ($session, $error) = Net::SNMP->session(
      -hostname   	=> $o_host,
      -port      	=> $o_port,
      -version		=> '3',
      -username		=> $o_secname,
      -timeout          => $o_timeout
    );
  }
} elsif ($o_protocol eq '2c') {
  # SNMPv2c Login
  verb("SNMP v2c login");
  ($session, $error) = Net::SNMP->session(
	-hostname	=> $o_host,
	-version	=> 2,
	-community	=> $o_community,
	-port		=> $o_port,
	-timeout	=> $o_timeout
    );
} else {
  # SNMPV1 login
  verb("SNMP v1 login");
  ($session, $error) = Net::SNMP->session(
	-hostname	=> $o_host,
	-community	=> $o_community,
	-port		=> $o_port,
	-timeout	=> $o_timeout
    );
}

if (!defined($session)) {
   printf("ERROR opening session: %s.\n", $error);
   exit $ERRORS{"UNKNOWN"};
}

if (defined($o_octetlength)) {
	my $oct_resultat=undef;
	my $oct_test= $session->max_msg_size();
	verb(" actual max octets:: $oct_test");
	$oct_resultat = $session->max_msg_size($o_octetlength);
	if (!defined($oct_resultat)) {
		 printf("ERROR: Session settings : %s.\n", $session->error);
		 $session->close;
		 exit $ERRORS{"UNKNOWN"};
	}
	$oct_test= $session->max_msg_size();
	verb(" new max octets:: $oct_test");
}

# Get description table
my $resultat = $session->get_table( 
  Baseoid => $descr_table 
);

if (!defined($resultat)) {
  printf("ERROR: Description table ($descr_table): %s.\n", $session->error);
  $session->close;
  exit $ERRORS{"UNKNOWN"};
}

my @tindex = undef;
my @oids = undef;
my @oid_perf = undef;
my @oid_reg_name = undef;
my @oid_reg_signal0 = undef;
my @oid_reg_signal1 = undef;
my @oid_reg_txrate = undef;
my @oid_reg_rxrate = undef;
my @index_descr = undef;
my $num_int = 0;


# Select interface by regexp of exact match 
# and put the oid to query in an array

verb("Filter : $o_descr");
foreach my $key ( keys %$resultat) {
  verb("OID : $key, Desc : $$resultat{$key}");
  # test by regexp or exact match
  my $test = defined($o_noreg) 
		? $$resultat{$key} eq $o_descr
		: $$resultat{$key} =~ /$o_descr/;
  if ($test) {
    # get the index number of the interface 
    my @oid_list = split (/\./,$key);
    $tindex[$num_int] = pop (@oid_list);
    # put the admin or oper oid in an array
    $oids[$num_int]= defined ($o_admin) ? $admin_table . $tindex[$num_int] 
			: $oper_table . $tindex[$num_int] ;
    $index_descr[$tindex[$num_int]] = $$resultat{$key};
    verb("Name : $$resultat{$key}, Index : $tindex[$num_int]");
    $num_int++;
  }
}
# No interface found -> error
if ( $num_int == 0 ) { print "ERROR : Unknown interface $o_descr\n" ; exit $ERRORS{"UNKNOWN"};}


my ($result,$resultf)=(undef,undef);
my $num_reg_int = 0;

if ($o_type eq 'mikrotik') {
  # Get wireless registration table
  my $resultreg = $session->get_table( 
    Baseoid => $reg_table
  );

  if (!defined($resultreg)) {
    printf("ERROR: Wireless registration table ($reg_table) : %s.\n", $session->error);
    $session->close;
    exit $ERRORS{"UNKNOWN"};
  }

  # Select interface by match to interface indexes above
  # and put the oid to query in an array

  foreach my $key ( keys %$resultreg) {
    my @oid_list = split (/\./,$key);
    foreach my $index ( @tindex ) {
      if ($oid_list[-1] eq $index ) {
        my $mac_oid = ".$oid_list[-7].$oid_list[-6].$oid_list[-5].$oid_list[-4].$oid_list[-3].$oid_list[-2].$oid_list[-1]";
        verb("Interface : $index_descr[$index], Index : $index, Reg MAC : $mac_oid");
        $oid_reg_name[$num_reg_int] = $index_descr[$index];
        $oid_reg_signal0[$num_reg_int] = $Mikrotik_table . ".3" . $mac_oid;
        $oid_reg_txrate[$num_reg_int] = $Mikrotik_table . ".8" . $mac_oid;
        $oid_reg_rxrate[$num_reg_int] = $Mikrotik_table . ".9" . $mac_oid;
        $num_reg_int++;
      }
    }
  }

  # Get the requested oid values
  $result = $session->get_request(
    Varbindlist => \@oids
  );
  if (!defined($result)) { printf("ERROR: Status table : %s.\n", $session->error); $session->close;
     exit $ERRORS{"UNKNOWN"};
  }

} elsif ( $o_type eq 'mikrotik_60g' ) {
  $num_reg_int = 1;
#  $oid_reg_signal0[0] = $Mikrotik_60g_table;

#  $oid_reg_name[0] = $index_descr[$index];
  $oid_reg_name[0] = 'wlan60-1';
  $oid_reg_signal0[0] = $Mikrotik_60g_table . '.12.1';
  $oid_reg_txrate[0] = $Mikrotik_60g_table . '.13.1';
  #$oid_reg_rxrate[0] = $Mikrotik_table . ".9" . $mac_oid;

} elsif ($o_type eq 'airfiber') {
  # Get wireless table
  my $resultreg = $session->get_table( 
    Baseoid => $reg_table
  );

  if (!defined($resultreg)) {
    printf("ERROR: Wireless table ($reg_table) : %s.\n", $session->error);
    $session->close;
    exit $ERRORS{"UNKNOWN"};
  }

  # Select interface by match to interface indexes above
  # and put the oid to query in an array

  foreach my $key ( keys %$resultreg) {
    my @oid_list = split (/\./,$key);
    my $int_oid = ".$oid_list[-6].$oid_list[-5].$oid_list[-4].$oid_list[-3].$oid_list[-2].$oid_list[-1]";
    $oid_reg_txrate[0] = $airFiber_table . ".3" . $int_oid;	# afLTUStaTxCapacity
    $oid_reg_rxrate[0] = $airFiber_table . ".4" . $int_oid;	# afLTUStaRxCapacity
    $oid_reg_signal0[0] = $airFiber_table . ".5" . $int_oid;	# afLTUStaRxPower0
    $oid_reg_signal1[0] = $airFiber_table . ".6" . $int_oid;	# afLTUStaRxPower1
  }
  $num_reg_int = 1;
  $oid_reg_name[0] = 'ath1';

} elsif ( $o_type eq 'mimosa' ) {
  $num_reg_int = 1;
  $oid_reg_name[0] = 'wifi0';
  $oid_reg_signal0[0] = $Mimosa_table . ".6.0";
  for (my $i=0;$i < $mimosa_chains; $i++) { 
    $oid_reg_txrate[$i] = $Mimosa_table . ".2.1.2." . ($i + 1);
    $oid_reg_rxrate[$i] = $Mimosa_table . ".2.1.5." . ($i + 1);
  }
}

# Get the perf value if -f (performance) option defined or -k (check bandwidth)
if ( (defined($o_perf)) || (defined($o_warn)) || (defined($o_crit)) || (defined($o_ratewarn)) || (defined($o_ratecrit)) || (defined($o_txratewarn)) || (defined($o_txratecrit)) || (defined($o_rxratewarn)) || (defined($o_rxratecrit)) ) {
  if ( $o_type eq 'mikrotik' ) {
    @oid_perf=(@oid_reg_signal0,@oid_reg_txrate,@oid_reg_rxrate);
  } elsif ( $o_type eq 'mikrotik_60g' ) {
    @oid_perf=(@oid_reg_signal0,@oid_reg_txrate);
  } elsif ( $o_type eq 'airfiber' ) {
    @oid_perf=(@oid_reg_signal0,@oid_reg_signal1,@oid_reg_txrate,@oid_reg_rxrate);
  } elsif ( $o_type eq 'mimosa' ) {
    @oid_perf=(@oid_reg_signal0,@oid_reg_txrate,@oid_reg_rxrate);
  }
  $resultf = $session->get_request(
    Varbindlist => \@oid_perf
  );
  if (!defined($resultf)) {
     printf("ERROR: Statistics table (@oid_perf): %s.\n", $session->error);
     $session->close;
     exit $ERRORS{"UNKNOWN"};
  }
}


$session->close;

my $num_ok=0;
my $final_status = 0;
my ($print_out,$perf_out)=(undef,undef);
my $details_out = "";

# make all checks and output for all interfaces
for (my $i=0;$i < $num_reg_int; $i++) { 
  my $rate_summary = "";
  #verb ("$oid_reg_name[$i], $oid_reg_signal0[$i], $oid_reg_txrate[$i], $oid_reg_rxrate[$i]");
  if ( $o_type eq 'mikrotik' ) {
    $rate_summary = sprintf(", %0.0f/%0.0f Mbps", ($$resultf{$oid_reg_rxrate[$i]}/1048576), ($$resultf{$oid_reg_txrate[$i]}/1048576));
    verb ("$i, $oid_reg_name[$i], $oid_reg_signal0[$i], $oid_reg_txrate[$i], $oid_reg_rxrate[$i]");
    verb ("$i, $oid_reg_name[$i], $$resultf{$oid_reg_signal0[$i]}, $$resultf{$oid_reg_txrate[$i]}, $$resultf{$oid_reg_rxrate[$i]}");
  } elsif ( $o_type eq 'mikrotik_60g' ) {
    $$resultf{$oid_reg_txrate[$i]} *= 1048576;	# Mikrotik reports their 60GHz rates in Gbps instead of bps
    $rate_summary = sprintf(", %0.0f Mbps", ($$resultf{$oid_reg_txrate[$i]}/1048576));
    verb ("$i, $oid_reg_name[$i], $oid_reg_signal0[$i], $oid_reg_txrate[$i]");
    verb ("$i, $oid_reg_name[$i], $$resultf{$oid_reg_signal0[$i]}, $$resultf{$oid_reg_txrate[$i]}");
  } elsif ( $o_type eq 'airfiber' ) {
    $$resultf{$oid_reg_rxrate[$i]} *= 1024;	# Ubiquiti reports their rates in Mbps instead of bps
    $$resultf{$oid_reg_txrate[$i]} *= 1024;
    $rate_summary = sprintf(", %0.0f/%0.0f Mbps", ($$resultf{$oid_reg_rxrate[$i]}/1048576), ($$resultf{$oid_reg_txrate[$i]}/1048576));
    verb ("$i, $oid_reg_name[$i], $oid_reg_signal0[$i], $oid_reg_signal1[$i], $oid_reg_txrate[$i], $oid_reg_rxrate[$i]");
    verb ("$i, $oid_reg_name[$i], $$resultf{$oid_reg_signal0[$i]}, $$resultf{$oid_reg_signal1[$i]}, $$resultf{$oid_reg_txrate[$i]}, $$resultf{$oid_reg_rxrate[$i]}");
  } elsif ( $o_type eq 'mimosa' ) {
    $$resultf{$oid_reg_signal0[$i]} /= 10;
    my ($txrate, $rxrate) = (0,0);
    $oid_reg_txrate[$mimosa_chains] = $Mimosa_table . ".2.1.2." . $mimosa_chains;
    $oid_reg_rxrate[$mimosa_chains] = $Mimosa_table . ".2.1.5." . $mimosa_chains;
    for (my $i=$mimosa_chains;$i > 0; $i--) { 
      $$resultf{$oid_reg_txrate[$i]} = $$resultf{$oid_reg_txrate[$i - 1]} * 1048576;
      $$resultf{$oid_reg_rxrate[$i]} = $$resultf{$oid_reg_rxrate[$i - 1]} * 1048576;
      verb ("tx $i: $oid_reg_txrate[$i - 1]  " . $$resultf{$oid_reg_txrate[$i]});
      verb ("rx $i: $oid_reg_rxrate[$i - 1]  " . $$resultf{$oid_reg_rxrate[$i]});
      # TODO: possibly warn if value different to the previous one
      $txrate += $$resultf{$oid_reg_txrate[$i]};
      $rxrate += $$resultf{$oid_reg_rxrate[$i]};
    }
    $$resultf{$oid_reg_txrate[0]} = $txrate;
    $$resultf{$oid_reg_rxrate[0]} = $rxrate;
    $rate_summary = ", ".($$resultf{$oid_reg_rxrate[0]}/1048576)."/".($$resultf{$oid_reg_txrate[0]}/1048576)." Mbps";
  }
  $print_out.=", " if (defined($print_out));
  $perf_out .= " " if (defined($perf_out)) ;
  # Get the status of the current interface
  my $signal = $$resultf{$oid_reg_signal0[$i]};
  if ( (defined($oid_reg_signal1[$i])) && ($$resultf{$oid_reg_signal1[$i]} > $$resultf{$oid_reg_signal0[$i]}) ) {
    $signal = $$resultf{$oid_reg_signal1[$i]};
  }
  my $int_status = 0;
  if ( (defined($o_crit)) && ( $signal <= $o_crit) ) {
    $int_status = 2;
    $final_status = 2;
    $details_out.=sprintf("signal %0.0f < %0.0f dBm critical\n",$signal, $o_crit);
  } elsif ( (defined($o_warn)) && ( $signal <= $o_warn) ) {
    $final_status = ($final_status==2) ? 2 : 1;
    $int_status = 1;
    $details_out.=sprintf("signal %0.0f < %0.0f dBm warning\n",$signal, $o_warn);
  } elsif (defined($o_warn)) {
    $details_out.=sprintf("signal %0.0f > %0.0f dBm\n",$signal, $o_warn);
  }

  my $rate = $$resultf{$oid_reg_txrate[$i]};
  if ( (defined($oid_reg_rxrate[$i])) && ($$resultf{$oid_reg_rxrate[$i]} < $$resultf{$oid_reg_txrate[$i]}) ) {
    $rate = $$resultf{$oid_reg_rxrate[$i]};
  }
  if ( (defined($o_ratecrit)) && ( $rate <= $o_ratecrit * 1048576) ) {
    $int_status = 2;
    $final_status = 2;
    $details_out.=sprintf("rate %0.0f < %0.0f Mbps critical\n",$rate/1048576, $o_ratecrit);
  } elsif ( (defined($o_ratewarn)) && ( $rate <= $o_ratewarn * 1048576) ) {
    $final_status = ($final_status==2) ? 2 : 1;
    $int_status = 1;
    $details_out.=sprintf("rate %0.0f < %0.0f Mbps warning\n",$rate/1048576, $o_ratewarn);
  } elsif (defined($o_ratewarn)) {
    $details_out.=sprintf("rate %0.0f > %0.0f Mbps\n",$rate/1048576, $o_ratewarn);
  }

  if ( (defined($o_txratecrit)) && ( $$resultf{$oid_reg_txrate[$i]} <= $o_txratecrit * 1048576) ) {
    $int_status = 2;
    $final_status = 2;
    $details_out.=sprintf("txrate %0.0f < %0.0f Mbps critical\n",$$resultf{$oid_reg_txrate[$i]}/1048576, $o_txratecrit);
  } elsif ( (defined($o_txratewarn)) && ( $$resultf{$oid_reg_txrate[$i]} <= $o_txratewarn * 1048576) ) {
    $final_status = ($final_status==2) ? 2 : 1;
    $int_status = 1;
    $details_out.=sprintf("txrate %0.0f < %0.0f Mbps warning\n",$$resultf{$oid_reg_txrate[$i]}/1048576, $o_txratewarn);
  } elsif (defined($o_txratewarn)) {
    $details_out.=sprintf("txrate %0.0f > %0.0f Mbps\n",$$resultf{$oid_reg_txrate[$i]}/1048576, $o_txratewarn);
  }
  if ( (defined($o_rxratecrit)) && ( $$resultf{$oid_reg_rxrate[$i]} <= $o_rxratecrit * 1048576) ) {
    $int_status = 2;
    $final_status = 2;
    $details_out.=sprintf("rxrate %0.0f < %0.0f Mbps critical\n",$$resultf{$oid_reg_rxrate[$i]}/1048576, $o_rxratecrit);
  } elsif ( (defined($o_rxratewarn)) && ( $$resultf{$oid_reg_rxrate[$i]} <= $o_rxratewarn * 1048576) ) {
    $final_status = ($final_status==2) ? 2 : 1;
    $int_status = 1;
    $details_out.=sprintf("rxrate %0.0f < %0.0f Mbps warning\n",$$resultf{$oid_reg_rxrate[$i]}/1048576, $o_rxratewarn);
  } elsif (defined($o_rxratewarn)) {
    $details_out.=sprintf("rxrate %0.0f > %0.0f Mbps\n",$$resultf{$oid_reg_rxrate[$i]}/1048576, $o_rxratewarn);
  }

  if (defined ($o_short)) {
    my $short_desc=undef;
    if ($o_short < 0) {$short_desc=substr($oid_reg_name[$i],$o_short);}
    else {$short_desc=substr($oid_reg_name[$i],0,$o_short);}
    if ( (defined($o_perf)) || (defined($o_warn)) || (defined($o_crit)) ) {
      $print_out.=sprintf("%s:%s (%0.0f dBm%s)",$short_desc, $status{$int_status}, $$resultf{$oid_reg_signal0[$i]}, $rate_summary );
    } else {
      $print_out.=sprintf("%s:%s",$short_desc, $status{$int_status} );
    }
  } else {
    if ( (defined($o_perf)) || (defined($o_warn)) || (defined($o_crit)) ) {
      $print_out.=sprintf("%s:%s (%0.0f dBm%s)",$oid_reg_name[$i], $status{$int_status}, $$resultf{$oid_reg_signal0[$i]}, $rate_summary );
    } else {
      $print_out.=sprintf("%s:%s",$oid_reg_name[$i], $status{$int_status} );
    }
  }

  # Get rid of special caracters for performance in oid_reg_name
  $oid_reg_name[$i] =~ s/'\/\(\)/_/g;
  if ( $int_status == 0) {
    $num_ok++;
  }
  if (defined ($o_perf)) {
    $perf_out .= " '" . $oid_reg_name[$i] ."_signal_dbm'=".$$resultf{$oid_reg_signal0[$i]};
    $perf_out .= ";$o_warn" if (defined($o_warn));
    $perf_out .= ";$o_crit" if ( (defined($o_warn)) && (defined($o_crit)) );

    if ($o_type eq 'mikrotik' || $o_type eq 'airfiber' || $o_type eq 'mimosa' ) {
      $perf_out .= " '" . $oid_reg_name[$i] ."_txrate_bps'=".$$resultf{$oid_reg_txrate[$i]};
      $perf_out .= ";" . ($o_txratewarn * 1048576) if (defined($o_txratewarn));
      $perf_out .= ";" . ($o_txratecrit * 1048576) if ( (defined($o_txratewarn)) && (defined($o_txratecrit)) );
      $perf_out .= " '" . $oid_reg_name[$i] ."_rxrate_bps'=".$$resultf{$oid_reg_rxrate[$i]};
      $perf_out .= ";" . ($o_rxratewarn * 1048576) if (defined($o_rxratewarn));
      $perf_out .= ";" . ($o_rxratecrit * 1048576) if ( (defined($o_rxratewarn)) && (defined($o_rxratecrit)) );
    }

    if ($o_type eq 'mikrotik_60g') {
      $perf_out .= " '" . $oid_reg_name[$i] ."_rate_bps'=".$$resultf{$oid_reg_txrate[$i]};
      $perf_out .= ";" . ($o_ratewarn * 1048576) if (defined($o_ratewarn));
      $perf_out .= ";" . ($o_ratecrit * 1048576) if ( (defined($o_ratewarn)) && (defined($o_ratecrit)) );
    }

  } 
}

# Only a few ms left...
alarm(0);

if ($final_status==0) {
  print $print_out, ($num_reg_int > 1) ? (":(".$num_ok." OK)") : "";
  if (defined ($o_perf)) { print " | ",$perf_out; }
  print "\n";
  print $details_out;
  exit $ERRORS{"OK"};
} elsif ($final_status==1) {
  print $print_out, ($num_reg_int > 1) ? (":(".$num_ok." OK): WARNING") : "";
  if (defined ($o_perf)) { print " | ",$perf_out; }
  print "\n";
  print $details_out;
  exit $ERRORS{"WARNING"};
} elsif ($final_status==2) {
  print $print_out, ($num_reg_int > 1) ? (":(".$num_ok." OK): CRITICAL") : "";
  if (defined ($o_perf)) { print " | ",$perf_out; }
  print "\n";
  print $details_out;
  exit $ERRORS{"CRITICAL"};
} else {
  print $print_out, ($num_reg_int > 1) ? (":(".$num_ok." OK): UNKNOWN") : "";
  if (defined ($perf_out)) { print " | ",$perf_out; }
  print "\n";
  print $details_out;
  exit $ERRORS{"UNKNOWN"};    
}
