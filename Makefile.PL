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
        if $ExtUtils::MakeMaker::VERSION < 6.4;
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
    my $version_set_manually = 1;
    if ($version_set_manually) {
      # we must control that the VERSION in CPAN.pm is the same as in the Makefile
      unshift @INC, "lib";
      require $version_from;
      open my $fh, "make the-release-name|" or die;
      my $have_version;
      while (<$fh>) {
        next unless /^version\s+([\d\._]+)/;
        $have_version = eval $1;
      }
      die "could not determine current version from Makefile" unless $have_version;
      eval q{
      no warnings "numeric";
      if ($CPAN::Checksums::VERSION != $have_version) {
        warn "Not equal: CPAN::Checksums::VERSION[$CPAN::Checksums::VERSION] Makefile version[$have_version]";
        $version_diff = 1;
      }
};
      die $@ if $@;
    } else {
      if ($sv_dot > $sv_from) {
        warn "setting some property to make a checkin of this file possible";
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
                              'Digest::MD5' => "2.36",
                              'Digest::SHA' => 0,
                              'DirHandle' => 0,
                              'File::Spec' => 0,
                              'File::Temp' => 0,
                              'IO::File' => "1.14",
                             },
              ($ExtUtils::MakeMaker::VERSION >= 6.3002 ?
               (LICENSE      => "perl") : (),
              ),
              'dist' => {
                         DIST_DEFAULT => join(" ",
                                              "verify-changes-date",
                                              "verify-changes-version",
                                              'Makefile',
                                              "META.yml",
                                              "setversion",
                                              "README",
                                              "all",
                                              "chlog",
                                              'tardist',
                                              ),
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

Makefile : lib/CPAN/Checksums.pm

README: Makefile
	$(PERL) -MPod::Text -e 'Pod::Text->new->parse_from_file(\*ARGV)' Checksums.pm > $@

chlog ::
	LC_ALL=en_GB.utf8 svn log -v -r `svnversion . | perl -ne '/(?:\d+:)?(\d+)[SM]*$$/&&print $$1'`:1 > ChangeLog.svn

the-release-name :
	$(NOECHO) $(ECHO) 'version ' $(VERSION)
	$(NOECHO) $(ECHO) 'release-name ' $(DISTVNAME).tar$(SUFFIX)

release ::
	perl -I../../CPAN/SVN/release-lib -S release $(DISTVNAME).tar$(SUFFIX)

sign:
	cpansign -s

META.yml: metafile
	$(CP) $(DISTVNAME)/META.yml  ./META.yml

verify-changes-date:
	@$(PERL) -ne 'BEGIN{my@t=(localtime)[5,4,3];$$t[0]+=1900;$$t[1]++;$$t=sprintf"%04d-%02d-%02d",@t}' \
		-e '$$ok++,exit if /^$$t\s/; END{die "Alert: did not find <$$t> in Changes file" unless $$ok}' Changes

verify-changes-version:
	@$(PERL) -ne '$$ok++,exit if /\b$(VERSION)\b/; END{die "Alert: did not find <$(VERSION)> in Changes file" unless $$ok}' Changes

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
