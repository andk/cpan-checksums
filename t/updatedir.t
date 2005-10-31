# -*- Mode: cperl; cperl-indent-level: 4 -*-

# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..6\n"; }
END {print "not ok 1\n" unless $loaded;}
use CPAN::Checksums;
$loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

my $ret = CPAN::Checksums::updatedir("t");
print $ret >= 1 ? "ok 2\n" : "# got ret[$ret] expected[>=1]\nnot ok 2\n";

chmod 0644, "t/43";
open F, ">t/43" or die;
print F "44\n";
close F;
$CPAN::Checksums::CAUTION=1;
my $warn;
$SIG{__WARN__} = sub { $warn = shift; };
$ret = CPAN::Checksums::updatedir("t");
print $ret == 2 ? "ok 3\n" : "# ret[$ret]\nnot ok 3\n";

print $warn =~ /^differing old\/new/m ? "ok 4\n" : "# warn[$warn]\nnot ok 4\n";

open F, ">t/43";
print F "43\n";
close F;
$warn = "";

$CPAN::Checksums::CAUTION=0;
$ret = CPAN::Checksums::updatedir("t");
print $ret == 2 ? "ok 5\n" : "# ret[$ret]\nnot ok 5\n";

print $warn eq "" ? "ok 6\n" : "# warn[$warn]\nnot ok 6\n";

