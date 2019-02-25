#!/usr/bin/perl
use 5.24.0;
use warnings;

# Core modules
use Data::Dumper;
use HTTP::Tiny;
use JSON::PP qw(decode_json); 

# This is a non-core module but commonly packaged
use IPC::System::Simple qw(capture system);

# Importing Sort::ByExample is optional, but you won't be able to set
# $ORDERED_JSON to 1 if it missing.
#use Sort::ByExample ();

$Data::Dumper::Terse = 1;

my $DEBUG = $ENV{DEBUG} // 1;
my $NFTLB_KEY = 'HoLa';
my $ORDERED_JSON = 0; # if 0, fuzz the order of the keys

reset_nftlb();
adjust_weight('10.0.2.5', 0);
validate_weight('10.0.2.5', 0);

sub reset_nftlb {
	# Adjust as necessary for your system. In my case, this guarantees
	# that the nftlb table is restored to a known state and that a fresh
	# instance of nftlb is running.
#	system('rc-service nftlb restart');
	system('nft flush ruleset');
	system('../src/nftlb -l 9 -k HoLa -c nftlb.json &');
	sleep 2;
}

sub adjust_weight {
	my ($addr, $weight) = @_;
	my $data = decode_json(curl_nftlb());
	for my $farm ($data->{farms}->@*) {
		for my $backend ($farm->{backends}->@*) {
			if ($addr ne $backend->{'ip-addr'}) {
				next;
			}
			if ($weight == 0) {
				$backend->{state} = 'down';
			} else {
				$backend->{state} = 'up';
				$backend->{weight} = $weight;
			}
			my $backend_path = sprintf '/farms/%s/backends/%s', $farm->{name}, $backend->{name};
                        my $new_farm = {
				farms => [{
					name     => $farm->{name},
					backends => [ $backend ]
				}]
                        };
			http_any_nftlb('DELETE', $backend_path);
			http_any_nftlb('PUT', '/farms', encode_json($new_farm));
		}
	}
}

sub validate_weight {
	my ($addr, $weight) = @_;
	my $data = decode_json(curl_nftlb());
	my %matched_by; # by farm name
	for my $farm ($data->{farms}->@*) {
		$matched_by{$farm->{name}} = 0;
		for my $backend ($farm->{backends}->@*) {
			if ($addr ne $backend->{'ip-addr'}) {
				next;
			}
			++$matched_by{$farm->{name}};
			if ($backend->{state} =~ m/error/) {
				# definitely not what we want
			} elsif ($weight == 0) {
				if ($backend->{state} eq 'down') {
					next;
				}
			} elsif ($weight == $backend->{weight} && $backend->{state} eq 'up') {
				next;
			}
			print "$farm->{name}/$backend->{name} is not as expected: ", Dumper $backend;
		}
	}
	for my $farm_name (grep { ! $matched_by{$_} } sort keys %matched_by) {
		say "No backend matches $addr in farm $farm_name. The PUT request was not honoured.";
	}
}

sub http_any_nftlb {
	if ($DEBUG) {
		warn Dumper \@_;
	}
	if (($ENV{HTTP_CLIENT} // '') eq 'native') {
		return http_nftlb(@_);
	}
	return curl_nftlb(@_);
}

sub get_nftlb_key {
	return $NFTLB_KEY;
}

sub curl_nftlb {
        my ($method, $path, $data) = @_;
	$method //= 'GET';
	$path //= '/farms';
        my $key = get_nftlb_key();
        my @args = ('-fsS', '-H', "Key: $key", '-X', $method, "http://127.0.0.1:5555$path");
        if (defined $data) {
		if ($DEBUG) {
			warn Dumper { sending_data => $data };
		}
                push @args, '-d', $data;
        }
	my $content = capture('curl', @args);
	if ($DEBUG && ! ($method eq 'GET' && $path eq '/farms')) {
		print STDERR Dumper { curl_response => $content };
	}
	return $content;
}

sub http_nftlb {
	my ($method, $path, $content) = @_;
	$method //= 'GET';
	$path //= '/farms';
	my $http = HTTP::Tiny->new(default_headers => { Key => get_nftlb_key() });
	my %options;
	if (defined $content) {
		if ($DEBUG) {
			warn Dumper { sending_data => $content };	
		}
		$options{content} = $content;
	}
	my $res = $http->request($method, "http://127.0.0.1:5555$path", \%options);
	if (! $res->{success}) {
		die "status => $res->{status}, content => $res->{content}";
	}
	if ($DEBUG && ! ($method eq 'GET' && $path eq '/farms')) {
		print STDERR Dumper { http_response => $res->{content} };
	}
	return $res->{content};
}

sub encode_json {
	my ($data) = @_;
	if ($ORDERED_JSON) {
		return safe_encode_json($data);
	}
	# Fuzz the key order
	my $coder = JSON::PP->new->utf8->sort_by(sub { int rand(2) } );
	while (1) {
		my $json = $coder->encode($data);
		# Make sure that name is the first backend key still. We already
		# know that nftlb will SEGFAULT if it isn't.
		if (index($json, '"backends":[{"name":') > -1) {
			return $json;
		}
	}
}

sub safe_encode_json {
        my $data = shift;
        my $cmp = Sort::ByExample->cmp(['name', 'ip-addr']);
        my $json = JSON::PP->new->utf8->sort_by(sub { $cmp->($JSON::PP::a, $JSON::PP::b) });                                                                            
        return $json->encode($data);
}
