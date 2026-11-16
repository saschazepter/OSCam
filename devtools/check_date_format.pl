#!/usr/bin/env perl
# Exercise date-format configuration, log routing, and WebIf's polling payloads.
use strict;
use warnings;
use Cwd qw(abs_path);
use File::Copy qw(copy);
use File::Path qw(make_path remove_tree);
use File::Temp qw(tempdir);
use HTTP::Tiny;
use IO::Socket::INET;
use JSON::PP qw(decode_json);
use POSIX qw(WNOHANG);

@ARGV == 1 or die "Usage: $0 /path/to/oscam-with-webif\n";
my $binary = abs_path($ARGV[0]);
defined($binary) && -x $binary or die "OSCam binary is not executable\n";
my $dir = tempdir('oscam-date-format-XXXXXX', TMPDIR => 1, CLEANUP => 0);
my ($server_pid, $passed);
END {
    my $result = $?;
    if ($server_pid) {
        kill 'TERM', $server_pid;
        for (1 .. 50) {
            if (waitpid($server_pid, WNOHANG) == $server_pid) {
                $server_pid = undef;
                last;
            }
            select undef, undef, undef, 0.05;
        }
        if ($server_pid) {
            kill 'KILL', $server_pid;
            waitpid($server_pid, 0);
        }
    }
    if (defined $dir) {
        if ($ENV{DATE_FORMAT_LOG_DIR}) {
            make_path($ENV{DATE_FORMAT_LOG_DIR});
            for my $name (qw(oscam.conf stdout.log oscam.log statistics.log)) {
                copy("$dir/$name", "$ENV{DATE_FORMAT_LOG_DIR}/$name") if -f "$dir/$name";
            }
        }
        if ($passed && !$ENV{DATE_FORMAT_KEEP}) {
            remove_tree($dir);
        } else {
            print "Date-format test artifacts: $dir\n";
        }
    }
    $? = $result;
}

my $listener = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
    Listen => 1, Proto => 'tcp') or die "Cannot allocate a test port: $!\n";
my $port = $listener->sockport;
close $listener;
make_path("$dir/tmp");
open my $config, '>', "$dir/oscam.conf" or die $!;
print {$config} <<"CONFIG";
[global]
logfile = $dir/oscam.log;stdout
usrfile = $dir/statistics.log
dateformat = stamp %Y-%m-%d %H:%M:%S
loghistorylines = 200
[dvbapi]
enabled = 0
[webif]
httpport = $port
serverip = 127.0.0.1
httpallowed = 127.0.0.1
httppollrefresh = 1
CONFIG
close $config;
$server_pid = fork();
defined($server_pid) or die "Cannot start OSCam: $!\n";
if (!$server_pid) {
    $ENV{TZ} = 'UTC';
    open STDOUT, '>', "$dir/stdout.log" or die $!;
    open STDERR, '>&', \*STDOUT or die $!;
    exec {$binary} $binary, '-c', $dir, '-t', "$dir/tmp", '-r', '0', '-w', '0';
    die "Cannot execute OSCam: $!\n";
}

my $http = HTTP::Tiny->new(timeout => 2, proxy => undef, http_proxy => undef,
    https_proxy => undef, no_proxy => '127.0.0.1');
my $base = "http://127.0.0.1:$port";
my $ready;
for (1 .. 20) {
    if (waitpid($server_pid, WNOHANG) == $server_pid) {
        $server_pid = undef;
        die "OSCam exited before WebIf started\n";
    }
    $ready = $http->get("$base/status.html");
    last if $ready->{success};
    select undef, undef, undef, 0.1;
}
$ready->{success} or die "WebIf did not start: $ready->{status}\n";

sub get_body {
    my ($path) = @_;
    my $response = $http->get("$base/$path");
    $response->{success} or die "GET $path failed: $response->{status}\n";
    return $response->{content};
}
sub status_json {
    return decode_json(get_body('oscamapi.json?part=status'))->{oscam};
}
sub save_format {
    my ($format) = @_;
    my $response = $http->post_form("$base/config.html", {
        part => 'global', action => 'execute', dateformat => $format,
    });
    $response->{success} or die "Configuration save failed: $response->{status}\n";
    return $response->{content};
}
sub read_file {
    my ($name) = @_;
    open my $file, '<', "$dir/$name" or die "$name: $!\n";
    local $/;
    return <$file> // '';
}

for (1 .. 3) {
    my $status = status_json();
    $status->{curdate} =~ /^\d\d\.\d\d\.\d\d$/ or die "Legacy API date changed\n";
    $status->{curtime} =~ /^\d\d:\d\d:\d\d$/ or die "Legacy API time changed\n";
    ($status->{display}{date} // '') =~ /^stamp \d{4}-\d\d-\d\d$/ or die "Polling lost the configured date\n";
    ($status->{display}{time} // '') =~ /^\d\d:\d\d:\d\d$/ or die "Polling lost the configured clock\n";
    for my $client (@{$status->{status}{client}}) {
        $client->{times}{login} =~ /^\d{4}-\d\d-\d\dT/ or die "Legacy API login changed\n";
        $client->{times}{loginfmt} =~ /^\d\d\.\d\d\.\d\d  \d\d:/ or die "Legacy loginfmt changed\n";
        $client->{times}{logindisplay} =~ /^stamp \d{4}-\d\d-\d\d / or die "Polling lost the configured login\n";
    }
}
my $html = get_body('status.html');
$html =~ /id="curtime"> stamp \d{4}-\d\d-\d\d \| / or die "Initial HTML date differs from polling\n";
my $xml = get_body('oscamapi.xml?part=status');
$xml =~ /login="\d{4}-\d\d-\d\dT/ or die "XML API login changed\n";
read_file('oscam.log') =~ /^stamp \d{4}-\d\d-\d\d /m or die "Custom timestamps disappeared from the logfile\n";
length(read_file('stdout.log')) or die "Ordinary log messages disappeared from stdout\n";
read_file('statistics.log') eq '' or die "Ordinary log messages reached the statistics file\n";

for my $invalid ('%c', '%H:%M:%S %d/%m/%Y', '%Y%n%H', '%100000Y', '%Y' x 8, '%Y' . 'x' x 31) {
    save_format($invalid) =~ /ERROR: Date format was not saved/ or die "Invalid format was accepted: $invalid\n";
    status_json()->{display}{date} =~ /^stamp / or die "Invalid format changed the running configuration\n";
}

my $escaped = 's"<\\%Y-%m-%d %H:%M';
save_format($escaped) =~ /Configuration was saved/ or die "Valid quoted format was rejected\n";
my $display = status_json()->{display}{date};
index($display, 's"<\\') == 0 or die "JSON display text was not escaped correctly\n";
get_body('status.html') =~ /s&quot;&lt;\\\d{4}-\d\d-\d\d/ or die "HTML display text was not escaped\n";
index(read_file('oscam.conf'), $escaped) >= 0 or die "Saved dateformat was corrupted\n";
save_format('') =~ /Configuration was saved/ or die "Resetting the format failed\n";
status_json()->{display}{date} =~ /^\d{4}-\d\d-\d\d$/ or die "Empty dateformat did not restore the default\n";

$passed = 1;
print "Date-format WebIf, API compatibility, escaping and log routing checks passed.\n";
