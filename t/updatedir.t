# -*- Mode: cperl; cperl-indent-level: 4 -*-

# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

use Test::More tests => 6;

use_ok("CPAN::Checksums");
my $ret = CPAN::Checksums::updatedir("t");
ok($ret >= 1, "ret[$ret]");

my $warn;
{
    chmod 0644, "t/43";
    local *F;
    open F, ">t/43" or die;
    print F "44\n";
    close F;
    local $CPAN::Checksums::CAUTION;
    $CPAN::Checksums::CAUTION=1;
    $SIG{__WARN__} = sub { $warn = shift; };
    $ret = CPAN::Checksums::updatedir("t");
    is($ret,2);

    like($warn,qr/^differing old\/new/m);

    open F, ">t/43";
    print F "43\n";
    close F;
    $warn="";
}

$ret = CPAN::Checksums::updatedir("t");
is($ret,2);

is($warn,"");

