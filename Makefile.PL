use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'CPAN::Checksums',
    'VERSION_FROM' => 'Checksums.pm', # finds $VERSION
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
	       PREOP => 'chmod +w $(DISTVNAME)/README && pod2text Checksums.pm > $(DISTVNAME)/README',
	       DIST_DEFAULT => 'all tardist',
	       COMPRESS => 'gzip -9f'
	      },
);
