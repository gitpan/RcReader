require RcReader;
use ExtUtils::MakeMaker;
$verbose = 1;
WriteMakefile(
  NAME => "RcReader.pm",
  DISTNAME => "RcReader.pm",
  VERSION_FROM => 'RcReader.pm',
  'dist' => {COMPRESS=>'gzip -9f', SUFFIX => '.gz'}
);
