use ExtUtils::MakeMaker qw(:DEFAULT);
my $Id = q$Id: Makefile.PL 146 2005-08-09 04:25:21Z k $;
our $VERSION = sprintf "%.3f", 1 + substr(q$Rev: 146 $,4)/1000;

{
  my $version_diff = 0; # we'll have to die if this becomes true
  my $version_from = File::Spec->catfile(qw(lib CPAN.pm));

  if ($ARGV[0] && $ARGV[0] eq "--setversion") {
    shift @ARGV;
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
    exit unless $version_diff;
  }
}

WriteMakefile(
              'NAME'	=> 'CPAN::Checksums',
              'VERSION_FROM' => 'Checksums.pm',
              'PREREQ_PM' => {
                              'File::Spec' => 0,
                              'DirHandle' => 0,
                              'IO::File' => 0,
                              'Digest::MD5' => 0,
                              'Compress::Zlib' => 0,
                              'Data::Dumper' => 0,
                              'Data::Compare' => 0,
                             },
              'dist' => {
                         DIST_DEFAULT => 'Makefile setversion README all chlog tardist',
                         COMPRESS => 'gzip -9f'
                        },
             );

sub MY::postamble {
  q{
setversion:
	$(PERL) Makefile.PL --setversion

README: Checksums.pm Makefile
	chmod +w $@
	pod2text Checksums.pm > $@

chlog ::
	LC_ALL=en_GB.utf8 svn log -v -r `svnversion . | perl -ne '/(?:\d+:)?(\d+)[SM]*$$/&&print $$1'`:1 > ChangeLog

Makefile.PL: $(VERSION_FROM)
	$(TOUCH) $@
}
}

sub MY::dist_ci {
  return qq{ci :
	svn ci
};
}

