#!/usr/bin/perl
#
# DESCRIPTION:
#	Test sending basic passive results to nsca
#
# COPYRIGHT:
#	Copyright (C) 2007 Altinity Limited
#	Copyright is freely given to Ethan Galstad if included in the NSCA distribution
#
# LICENCE:
#	GNU GPLv2

use strict;
use NSCATest;
use Test::More;

plan tests => 2;

my $data = [ 
	["hostname", "0", "Plugin output"],
	["hostname-with-other-bits", "1", "More data to be read"],
	["hostname.here", "2", "Check that ; are okay to receive"],
	["host", "service", 0, "A good result here"],
	["host54", "service with spaces", 1, "Warning! My flies are undone!"],
	["host-robin", "service with a :)", 2, "Critical? Alert! Alert!"],
	["host-batman", "another service", 3, "Unknown - the only way to travel"],
	];

foreach my $type qw(--single --daemon) {
	my $nsca = NSCATest->new( config => "basic" );

	$nsca->start($type);
	$nsca->send($data);
	sleep 1;		# Need to wait for --daemon to finish processing

	my $output = $nsca->read_cmd;
	is_deeply($data, $output, "Got all data as expected");

	$nsca->stop;
}
