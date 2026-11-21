use strict;
use warnings;
use Test::More;
use File::Basename qw(dirname);
use File::Copy qw(copy);
use File::Path qw(make_path);
use File::Spec;
use File::Temp qw(tempdir);
use Cwd qw(abs_path);
use Time::HiRes ();

my $root = abs_path(File::Spec->catdir(dirname(__FILE__), '..'));
my $enum4linux = File::Spec->catfile($root, 'enum4linux.pl');
my $mock_samba = File::Spec->catfile($root, 't', 'lib', 'mock_samba.pl');
my $tmp = tempdir(CLEANUP => 1);
my $mock_bin = File::Spec->catdir($tmp, 'mock-bin');
make_path($mock_bin);
chmod 0755, $mock_samba;

foreach my $command (qw(nmblookup net rpcclient smbclient polenum ldapsearch)) {
	my $target = File::Spec->catfile($mock_bin, $command);
	unless (symlink($mock_samba, $target)) {
		copy($mock_samba, $target) or die "Can't install mock $command: $!";
		chmod 0755, $target;
	}
}

my $real_path = $ENV{PATH};

sub run_enum {
	my (%args) = @_;
	my @argv = @{ $args{argv} || [] };
	my %mock_env = %{ $args{env} || {} };
	my $state = tempdir(CLEANUP => 1);
	my $output_file = File::Spec->catfile($state, 'stdout');
	my $started = Time::HiRes::time();
	my $pid = fork();
	die "fork failed: $!" unless defined($pid);
	if ($pid == 0) {
		open(STDOUT, '>', $output_file) or exit 127;
		open(STDERR, '>&', STDOUT) or exit 127;
		$ENV{PATH} = "$mock_bin:$real_path";
		$ENV{MOCK_STATE} = $state;
		delete @ENV{qw(MOCK_AUTH_FAIL MOCK_DELAY MOCK_TRANSIENT_HOST MOCK_TRANSIENT_ATTEMPTS)};
		foreach my $key (keys %mock_env) {
			$ENV{$key} = $mock_env{$key};
		}
		exec($^X, $enum4linux, @argv);
		exit 127;
	}
	waitpid($pid, 0);
	my $status = $?;
	my $elapsed = Time::HiRes::time() - $started;
	my $output = slurp($output_file);
	return ($status, $output, $state, $elapsed);
}

sub slurp {
	my ($path) = @_;
	open my $fh, '<', $path or return '';
	local $/;
	my $content = <$fh>;
	close $fh;
	return defined($content) ? $content : '';
}

sub matching_lines {
	my ($output, $pattern) = @_;
	return grep { $_ =~ $pattern } split(/\n/, $output);
}

sub events {
	my ($state) = @_;
	my @events;
	open my $fh, '<', File::Spec->catfile($state, 'events.log') or return @events;
	while (my $line = <$fh>) {
		chomp $line;
		my ($time, $command, $host, $args) = split(/\t/, $line, 4);
		push @events, {
			time => $time,
			command => $command,
			host => $host,
			args => defined($args) ? $args : '',
		};
	}
	close $fh;
	return @events;
}

sub smbclient_ipc_events {
	my ($state, $host) = @_;
	return grep {
		$_->{command} eq 'smbclient'
			&& $_->{args} =~ /ipc\$/ 
			&& (!defined($host) || $_->{host} eq $host)
	} events($state);
}

sub batch_succeeded {
	my ($output) = @_;
	return $output =~ /Batch complete: (\d+) succeeded/ ? $1 : undef;
}

subtest 'CIDR expansion and target deduplication' => sub {
	my ($status, $output) = run_enum(
		argv => [
			'-U',
			'--threads', '4',
			'--rate', '50',
			'--targets', '10.10.0.0/30,10.10.0.1,10.10.0.2',
		],
	);
	diag($output) if $status != 0;
	is($status, 0, 'batch exits successfully');
	is(batch_succeeded($output), 2, 'network and broadcast addresses are skipped and overlaps are deduplicated');
	my @targets = matching_lines($output, qr/^Target \.\.\.\.+ 10\.10\.0\./);
	is(scalar(@targets), 2, 'each unique host is enumerated once');
};

subtest 'transient failures retry only the affected host' => sub {
	my ($status, $output, $state) = run_enum(
		argv => [
			'-U',
			'--threads', '2',
			'--rate', '20',
			'--retries', '2',
			'--retry-delay', '0.01',
			'--targets', '10.20.0.1,10.20.0.2',
		],
		env => {
			MOCK_TRANSIENT_HOST => '10.20.0.1',
			MOCK_TRANSIENT_ATTEMPTS => 1,
		},
	);
	is($status, 0, 'retry succeeds');
	is(batch_succeeded($output), 2, 'both hosts finish');
	is(scalar(matching_lines($output, qr/Transient failure on 10\.20\.0\.1/)), 1, 'one retry is scheduled');
	is(scalar(smbclient_ipc_events($state, '10.20.0.1')), 2, 'failed host is tried twice');
	is(scalar(smbclient_ipc_events($state, '10.20.0.2')), 1, 'healthy host is not retried');
};

subtest 'authentication failures never retry' => sub {
	my ($status, $output, $state) = run_enum(
		argv => [
			'-U',
			'--threads', '2',
			'--rate', '20',
			'--retries', '5',
			'--retry-delay', '0.01',
			'--targets', '10.30.0.1,10.30.0.2',
		],
		env => { MOCK_AUTH_FAIL => 1 },
	);
	isnt($status, 0, 'batch fails');
	is(scalar(smbclient_ipc_events($state)), 2, 'one authentication attempt per host');
	is(scalar(matching_lines($output, qr/retrying in/)), 0, 'no retry is scheduled');
	is(scalar(matching_lines($output, qr/not retrying to avoid account lockout/)), 2, 'lockout protection is reported');
	is(batch_succeeded($output), 0, 'no hosts succeed');
};

subtest 'host timeout stops a wedged SMB client' => sub {
	my ($status, $output, undef, $elapsed) = run_enum(
		argv => [
			'-U',
			'--threads', '1',
			'--rate', '20',
			'--retries', '0',
			'--host-timeout', '0.2',
			'--targets', '10.35.0.1',
		],
		env => { MOCK_DELAY => '2' },
	);
	isnt($status, 0, 'timed-out batch fails');
	like($output, qr/timed out after 0\.2s/, 'timeout is reported');
	cmp_ok($elapsed, '<', 2, 'hung host worker is terminated promptly');
};

subtest 'duplicate result records are emitted once' => sub {
	my ($status, $output) = run_enum(
		argv => [
			'-U', '-S',
			'--threads', '1',
			'--targets', '10.40.0.1',
		],
	);
	is($status, 0, 'single host succeeds');
	is(scalar(matching_lines($output, qr/Account: alice/)), 1, 'duplicate querydispinfo account is deduplicated');
	is(scalar(matching_lines($output, qr/user:\[alice\]/)), 0, 'same account from enumdomusers is deduplicated');
	is(scalar(matching_lines($output, qr/user:\[bob\]/)), 1, 'unique account remains');
	is(scalar(matching_lines($output, qr{^//10\.40\.0\.1/public\tMapping:})), 1, 'duplicate share result is deduplicated');
};

subtest 'host start rate is limited' => sub {
	my ($status, $output, undef, $elapsed) = run_enum(
		argv => [
			'-U',
			'--threads', '5',
			'--rate', '5',
			'--targets', join(',', map { "10.50.0.$_" } 1 .. 5),
		],
	);
	is($status, 0, 'rate-limited batch succeeds');
	is(batch_succeeded($output), 5, 'all rate-limited hosts finish');
	cmp_ok($elapsed, '>=', 0.7, 'five starts at five per second respect the rate limit');
};

subtest 'host concurrency is limited' => sub {
	my ($status, $output, undef, $elapsed) = run_enum(
		argv => [
			'-U',
			'--threads', '2',
			'--rate', '100',
			'--targets', join(',', map { "10.60.0.$_" } 1 .. 6),
		],
		env => { MOCK_DELAY => '0.1' },
	);
	is($status, 0, 'concurrency-limited batch succeeds');
	is(batch_succeeded($output), 6, 'all concurrency-limited hosts finish');
	cmp_ok($elapsed, '>=', 1.1, 'two workers serialize more than one wave');
};

subtest '500 hosts complete within the ten-minute budget' => sub {
	my @targets;
	push @targets, map { "10.70.0.$_" } 1 .. 250;
	push @targets, map { "10.70.1.$_" } 1 .. 250;
	my ($status, $output, undef, $elapsed) = run_enum(
		argv => [
			'-U',
			'--threads', '32',
			'--rate', '50',
			'--retries', '2',
			'--retry-delay', '0.05',
			'--host-timeout', '10',
			'--targets', join(',', @targets),
		],
	);
	is($status, 0, '500-host batch succeeds');
	is(batch_succeeded($output), 500, 'all 500 hosts are enumerated');
	cmp_ok($elapsed, '<', 600, 'batch finishes inside the ten-minute requirement');
};

done_testing();
