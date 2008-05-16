use ExtUtils::MakeMaker qw(:DEFAULT);
my $Id = q$Id: Makefile.PL 3 2005-10-30 13:58:32Z k $;

my $version_diff = 0; # we'll have to die if this becomes true
{
  my $version_from = q(lib/CPAN/Checksums.pm);

  {
    local $^W;
    $ExtUtils::MakeMaker::VERSION = eval $ExtUtils::MakeMaker::VERSION;
    warn "Your MakeMaker is a bit dated[$ExtUtils::MakeMaker::VERSION].\nYou should get a new one\n"
        if $ExtUtils::MakeMaker::VERSION < 6.0;
  }

  if ($ARGV[0] && $ARGV[0] eq "--setversion") {
    die "Your perl is a bit dated[$]].\nDo not make a release with it\n" if $] < 5.008;
    die "Your MakeMaker is a bit dated[$ExtUtils::MakeMaker::VERSION].\nDo not make a release with it\n"
        if $ExtUtils::MakeMaker::VERSION < 6.3004;
    die "Your MakeMaker doesn't do the sign woodoo" unless
        MM->can("signature_target");
    shift @ARGV;
    local $ENV{LANG} = "C";
    open my $st, "svn st -u|" or die;
    my $dirty = 0;
    while (<$st>) {
      next if /^\?/;
      next if /^Head revision:/;
      next if /^Status against revision:/;
      print;
      $dirty++;
    }
    close $st;
    die "Not everything checked in?" if $dirty;

    # $re parses the upper boundary of the output of svnversion
    my $re = qr/(?:\d+:)?(\d+)[SM]*$/;
    my($sv_dot)  = `svnversion .`             =~ $re;
    my($sv_from) = `svn st -u -v $version_from`  =~ /^.{8}\s*(?:\d+)\s*(\d+)/;
    die "Could not determine sv_from or sv_dot"
        unless $sv_from > 0 && $sv_dot > 0;
    if ($sv_dot > $sv_from) {
      warn "setting property cpan:release to 'after_$sv_dot' to enable checkin";
      0==system(svn => "propset",
                "cpan:release",
                "after_$sv_dot",
                $version_from) or die;
      warn "checking in to get the version up to the bleading edge";
      0==system(svn => "ci",
                "-m",
                "Property set for release after_$sv_dot",
                $version_from) or die;
      # will have to die after Makefile is rewritten:
      $version_diff = 1;
    }
    exit unless $version_diff;
  }
}
WriteMakefile(
              'NAME'	=> 'CPAN::Checksums',
              'VERSION_FROM' => 'lib/CPAN/Checksums.pm',
              (MM->can("signature_target") ? (SIGN => 1) : ()),
              'PREREQ_PM' => {
                              'Compress::Bzip2' => 0,
                              'Compress::Zlib' => 0,
                              'Data::Compare' => 0,
                              'Data::Dumper' => 0,
                              'Digest::MD5' => 0,
                              'Digest::SHA' => 0,
                              'DirHandle' => 0,
                              'File::Spec' => 0,
                              'File::Temp' => 0,
                              'IO::File' => 0,
                             },
              ($ExtUtils::MakeMaker::VERSION >= 6.3002 ?
               (LICENSE      => "perl") : (),
              ),
              'dist' => {
                         DIST_DEFAULT => 'Makefile setversion README all chlog tardist',
                         COMPRESS => 'gzip -9f'
                        },
             );

if ($version_diff){
  die "
==> I had to update some \$VERSIONs <==
==> Your Makefile has been rebuilt. <==
==> Please rerun the make command.  <==
";
}

sub MY::postamble {
  q{
setversion:
	$(PERL) Makefile.PL --setversion

Makefile : Checksums.pm

README: Makefile
	$(PERL) -MPod::Text -e 'Pod::Text->new->parse_from_file(\*ARGV)' Checksums.pm > $@

chlog ::
	LC_ALL=en_GB.utf8 svn log -v -r `svnversion . | perl -ne '/(?:\d+:)?(\d+)[SM]*$$/&&print $$1'`:1 > ChangeLog.svn

release ::
	perl -I../../CPAN/SVN/release-lib -S release $(DISTVNAME).tar$(SUFFIX)

sign:
	cpansign -s

}
}

sub MY::dist_ci {
  return qq{ci :
	svn ci
};
}

sub MY::dist_test {
  return q{
# if we depend on $(DISTVNAME).tar$(SUFFIX), then the rest of the
# Makefile breaks our intent to NOT remake dist
disttest :
	rm -rf $(DISTVNAME)
	tar xvzf $(DISTVNAME).tar$(SUFFIX)
	cd $(DISTVNAME) && $(ABSPERLRUN) Makefile.PL
	cd $(DISTVNAME) && $(MAKE) $(PASTHRU)
	cd $(DISTVNAME) && $(MAKE) test $(PASTHRU)
}
}
