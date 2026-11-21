#!/usr/bin/env perl
use strict;
use warnings;
use File::Basename qw(basename);
use Fcntl qw(:flock);
use Time::HiRes ();

my $command = basename($0);
my $state = $ENV{MOCK_STATE} || die "MOCK_STATE is required\n";
my ($host);
foreach my $argument (@ARGV) {
	if ($argument =~ /((?:\d{1,3}\.){3}\d{1,3})/) {
		$host = $1;
		last;
	}
}
$host = 'unknown' unless defined($host);

Time::HiRes::sleep($ENV{MOCK_DELAY}) if defined($ENV{MOCK_DELAY}) && $ENV{MOCK_DELAY} > 0;
log_event($command, $host, @ARGV);

if ($command eq 'smbclient' && is_ipc_share(@ARGV)) {
	if ($ENV{MOCK_AUTH_FAIL}) {
		print "session setup failed: NT_STATUS_LOGON_FAILURE\n";
		exit 1;
	}
	if (transient_attempt($host)) {
		print "NT_STATUS_IO_TIMEOUT\n";
		exit 1;
	}
}

if ($command eq 'nmblookup') {
	print "Looking up status of $host\n";
	print "\tMOCKDOMAIN      <00> - <GROUP> B <ACTIVE>\n";
	exit 0;
}

if ($command eq 'smbclient') {
	if (is_ipc_share(@ARGV)) {
		print "Domain=[MOCKDOMAIN] OS=[MockOS] Server=[MockSMB]\n";
		print "case_sensitive\n";
		exit 0;
	}
	if (grep { $_ eq '-L' } @ARGV) {
		print "\n\tSharename       Type      Comment\n";
		print "\t---------       ----      -------\n";
		print "\tpublic          Disk      Public\n";
		print "\tpublic          Disk      Duplicate\n";
		exit 0;
	}
	print "blocks of size 1024. blocks available\n";
	exit 0;
}

if ($command eq 'rpcclient') {
	my $joined = join(' ', @ARGV);
	if ($joined =~ /lsaquery/) {
		print "Domain Sid: S-1-5-21-111-222-333\n";
	} elsif ($joined =~ /lookupnames/) {
		print "S-1-5-21-111-222-333-500\n";
	} elsif ($joined =~ /querydispinfo/) {
		print "index: 0x1 RID: 0x1f4 acb: 0x10 Account: alice Name: Alice\n";
		print "index: 0x1 RID: 0x1f4 acb: 0x10 Account: alice Name: Alice\n";
	} elsif ($joined =~ /enumdomusers/) {
		print "user:[alice] rid:[0x1f4]\n";
		print "user:[alice] rid:[0x1f4]\n";
		print "user:[bob] rid:[0x1f5]\n";
	} else {
		print "ok\n";
	}
	exit 0;
}

if ($command eq 'net') {
	print "MOCKDOMAIN\\alice\n";
	exit 0;
}

exit 0;

sub log_event {
	my @record = @_;
	open my $fh, '>>', "$state/events.log" or die "Can't write events.log: $!\n";
	flock($fh, LOCK_EX);
	print $fh join("\t", Time::HiRes::time(), @record) . "\n";
	close $fh;
}

sub transient_attempt {
	my ($target) = @_;
	my $host_value = $ENV{MOCK_TRANSIENT_HOST};
	return 0 unless defined($host_value) && $host_value eq $target;
	my $limit = defined($ENV{MOCK_TRANSIENT_ATTEMPTS})
		? $ENV{MOCK_TRANSIENT_ATTEMPTS}
		: 1;
	my $safe_target = $target;
	$safe_target =~ s/[^A-Za-z0-9_.-]/_/g;
	my $path = "$state/transient-$safe_target";
	open my $fh, '+>>', $path or die "Can't write transient state: $!\n";
	flock($fh, LOCK_EX);
	seek($fh, 0, 0);
	my $count = <$fh>;
	chomp($count) if defined($count);
	$count = 0 unless defined($count) && $count =~ /^\d+$/;
	$count++;
	seek($fh, 0, 0);
	truncate($fh, 0);
	print $fh "$count\n";
	close $fh;
	return $count <= $limit ? 1 : 0;
}

sub is_ipc_share {
	my @arguments = @_;
	return grep { m{/ipc\$$} } @arguments;
}
