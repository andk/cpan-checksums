# -*- Mode: cperl; cperl-indent-level: 4 -*-

# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

use Test::More;
my $HAVE_TIME_HIRES = 0;

my $plan = 20;
if (eval { require Time::HiRes; 1; }) {
    $HAVE_TIME_HIRES = 1;
}
plan tests => $plan;

use_ok("CPAN::Checksums");
my $ret = CPAN::Checksums::updatedir("t");
ok($ret >= 1, "ret[$ret]");

my $warn;
{
    chmod 0644, "t/43";
    local *F;
    open F, ">t/43" or die;
    print F "4321\n" x 1_000_000;
    close F;
    local $CPAN::Checksums::CAUTION;
    $CPAN::Checksums::CAUTION=1;
    $SIG{__WARN__} = sub { $warn = shift; };
    $ret = CPAN::Checksums::updatedir("t");
    is($ret,2,"changed once");

    like($warn,qr/^differing old\/new/m,"warning emitted");

    my $start = $HAVE_TIME_HIRES ? Time::HiRes::time() : time;
    $ret = CPAN::Checksums::updatedir("t");
    my $tooktime = ($HAVE_TIME_HIRES ? Time::HiRes::time() : time) - $start;
    is($ret,1,"no change tooktime[$tooktime]");

    open F, ">t/43";
    print F "43\n";
    close F;
    $warn="";
}

$ret = CPAN::Checksums::updatedir("t");
is($ret,2,"changed again");
is($warn,"","no warning");
my @stat = stat "t/CHECKSUMS";
sleep 2;
$ret = CPAN::Checksums::updatedir("t");
is($ret,1,"no change");
my @stat2 = stat "t/CHECKSUMS";
for my $s (0..7,9..12) { # 8==atime not our business
    is($stat[$s],$stat2[$s],"unchanged stat element $s");
}
