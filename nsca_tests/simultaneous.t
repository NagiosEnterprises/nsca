#!/usr/bin/perl
#
# DESCRIPTION:
#       Test sending lots of results at the same time
#
# COPYRIGHT:
#       Copyright (C) 2007 Altinity Limited
#       Copyright is freely given to Ethan Galstad if included in the NSCA distribution
#
# LICENCE:
#       GNU GPLv2


use strict;
use NSCATest;
use Test::More;
use Clone qw(clone);
use Parallel::Forker;

my $iterations = 100;
my $timeout = 8;

plan tests => 4;

my $data = [
        ["hostname", "0", "Plugin output"],
        ["hostname-with-other-bits", "1", "More data to be read"],
        ["hostname.here", "2", "Check that ; are okay to receive"],
        ["host", "service", 0, "A good result here"],
        ["host54", "service with spaces", 1, "Warning! My flies are undone!"],
        ["host-robin", "service with a :)", 2, "Critical? Alert! Alert!"],
        ["host-batman", "another service", 3, "Unknown - the only way to travel"],
	];


my $Fork = Parallel::Forker->new;
$SIG{CHLD} = sub { $Fork->sig_child; };
$SIG{TERM} = sub { $Fork->kill_tree_all('TERM') if $Fork; die "Quitting..."; };

foreach my $type qw(--single --daemon) {
	my $expected = [];
	my $nsca = NSCATest->new( config => "basic", timeout => $timeout );

	$nsca->start($type);

	for (my $i = 0; $i < $iterations; $i++) {
		my $c = clone($data);
		push @$c, [ "host$i", 2, "Some unique data: ".rand() ];
		push @$expected, @$c;
		$Fork->schedule( 
			run_on_start => sub { $nsca->send($c) },
			);
	}

	$Fork->ready_all;
	$Fork->wait_all;

	sleep 1;		# Need to wait for --daemon to finish processing

	my $output = $nsca->read_cmd;

	is( scalar @$output, scalar @$expected, "Got all ".scalar @$expected." packets of data" );
	is_deeply_sorted( $output, $expected, "All data as expected" );

	$nsca->stop;
}

sub is_deeply_sorted {
	my ($expected, $against, $text) = @_;
	my $e = [ sort map { join(";", map { $_ } @$_) } @$expected ];
	my $a = [ sort map { join(";", map { $_ } @$_) } @$against ];
	is_deeply($e, $a, $text);
}

