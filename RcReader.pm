#!/usr/bin/perl
################################################################################
# RcReader.pm	version 0.5.9 (pre-release)
# AUTHOR	: Samuel Behan <behan@frida.fri.utc.sk> (c) 2000-2001
# HOMEPAGE	: http://frida.fri.utc.sk/~behan/devel/rc_reader
# LICENSE	: GNU GPL v2 or later (see file LICENSE)
################################################################################

##
# define system wide constants (constant subroutines)
sub CPP_NO_INCLUDE()	{ 001; }	#ignore %include directive
sub CPP_NO_SUBINCLUDE()	{ 002; }	#ignore %include in included files
sub CPP_NO_ERROR()	{ 004; }	#ignore %error directive
sub CPP_NO_ECHO()	{ 010; }	#ignore %echo directive
sub CPP_NO_EXEC()	{ 020; }	#disable external command execution
sub CPP_NO_MARK()	{ 040; }	#do not mark file for parser
#define	INCLUDED	= 100		#internal modificator

package RcReader;
use strict;
use integer;
use vars (qw(@ISA @EXPORT @EXPORT_OK $VERSION $AUTHOR),
	  qw(%OPTIONS));
require Exporter;
@ISA		= qw(Exporter);
@EXPORT		= qw();
@EXPORT_OK	= qw( rc_cpp rc_init rc_parse rc_set rc_stop rc_free
			rc_eval rc_escape );
$VERSION	= '0.5.9';
$AUTHOR		= 'Samuel Behan <behan@frida.fri.utc.sk>';

##
# Preprocess given file sub(*FILE_IN, *FILE_OUT, [$ident, $options, %hash])
sub rc_cpp(\*\*;$$\%)
{
  my($FI, $FO, $line, $lcnt, $linenum, $condition, $retval, $ident, $cmd, $inblock, %HASH);
  $FI	= shift; $FO	= shift;			#file pointers
  $ident	= (defined($_[0]) ? $_[0] : '%');	#identificator
  %HASH		= %{(defined($_[2]) ? $_[2] : \%ENV)};	#my HASH array
  $linenum	= $lcnt	= $inblock	= 0;		#init

  while($line	= <$FI>)
  { $linenum++;
    if($line !~ s/^$ident(ifdef|ifndef|if|else|elsif|elseif|endif|define|undef|undefine|print|echo|warning|error|include|dnl)//o)
    { syswrite($FO, $line, length($line)) || return -10; $lcnt++; next; }
    $cmd	= $1;
    #commands execution
    if($cmd eq "if" || (($cmd eq "elsif" || $cmd eq "elseif") && ($inblock > 0)))
    { $condition	= $line; chomp($condition);
      $condition	=~ s/(\d+|".*?"|'.*?'|eq|ne|\/.*\/i?|defined|length|substr|(\$?\w+))/${(($2)?\("\$HASH{$2}"):\$&)}/og;
      COND_BLOCK:      $inblock++;
      if($condition eq '') { return (-2, "if", $linenum); }
      else 
      { local $SIG{__DIE__}	= sub { $retval	= -3; };
        local $SIG{__WARN__}	= sub { $retval	= -3; };
        $retval	= eval("if($condition) { return 1; } else { return 0; }"); }
      $condition	= undef;
      if($retval == 0)
      { IGNORE_BLOCK:
        my($level); $level	= 1;
	($_[1] && 040) || syswrite($FO, "${ident}line $linenum\n");
        while(($level > 0) && ($line = <$FI>))
        { $linenum++;
	  if($line	=~ /^${ident}(if|ifdef)\s+/o)	{ $level++; } 
	  elsif($line	=~ /^${ident}endif/o)		{ $level--; }
	  elsif($line	=~ /^${ident}else/o)		{ $level=0; } }
	  if($level > 0) { return (-1, $cmd, $linenum); }
	($_[1] && 040) || syswrite($FO, "${ident}line $linenum\n");
      } elsif($retval != 1) { return ($retval, $cmd, $linenum); }
    }
    elsif($cmd	eq "elsif" || $cmd eq "elseif")
    { return (-6, "$cmd", $linenum); }
    elsif($cmd	eq "ifdef")		#ifdef(SYMBOL)
    { $condition	= $line; chomp($condition);
      $condition	=~ s/(\d+|(\$?\w+))/${(($2)?\("\$HASH{$2}"):\$&)}/og;
      goto COND_BLOCK; }
    elsif($cmd eq "ifndef")
    { $condition	= $line; chomp($condition);
      $condition	=~ s/(\d+|(\$?\w+))/${(($2)?\("!\$HASH{$2}"):\("!$&"))}/og;
      goto COND_BLOCK; }
    elsif($cmd	eq "else")
    { if($inblock <= 0) { return (-6, $cmd, $linenum); }
      goto IGNORE_BLOCK; }
    elsif($cmd	eq "endif")		#endif
    { if($inblock <= 0) { return (-2, "endif", $linenum); }
      $inblock--; }
    elsif($cmd	eq "define")		#define SYMBOL VALUE
    { $line =~ /^\s*(\S+)(\s+(.+))?\s*$/o; my($var, $value) = ($1, $3);
      defined($var)	|| return (-2, "define", $linenum);
      if(!defined($value)) { $value	= 1; }
      else
      { my($quot, $x);
        if(!($_[1] & 020) && $value =~ s/^\s*\$\((.+?)\)\s*$/${\($x=`$1`)}/o){}
        elsif($value =~ s/^(\"|\')//o && ($quot = $1) && $value !~ s/$quot$//)
        { while($line = <$FI>)
	  { $linenum++; $value	.= $line; ($value =~ s/$quot\s*$//) && last; }
	  defined($line) || return (-1, $cmd, $linenum); } }
	chomp($value);
	$value	=~ s/\$(\{(\w+)\}|(\w+))/${ \$HASH{$2 || $3} }/og;
	$HASH{$var}	= $value; }
    elsif($cmd eq "undef" || $cmd eq "undefine")	#undef SYMBOL
    { $line	=~ /^\s+(\w+)\s*$/o;
      defined($1) || return (-2, "undef", $linenum);
      delete($HASH{$1}); }
    elsif($cmd eq "print" || $cmd eq "echo" || $cmd eq "warning") #echo MESSAGE
    { ($_[1] & 010) && next; chomp($line);
      $line	=~ s/\$(\{(\w+)\}|(\w+))/${ \$HASH{$2 || $3} }/og;
      warn($ident.$cmd.$line."\n"); }
    elsif($cmd eq "error")		#error MESSAGE
    { ($_[1] & 004) && next; chomp($line);
      $line	=~ s/\$(\{(\w+)\}|(\w+))/${ \$HASH{$2 || $3} }/og;
      warn($ident."error$line\n"); 
      return (-5, "error", $linenum); }
    elsif($cmd eq "include") 		#include FILE
    { (($_[1] & 001) || (($_[1] & (002|100)))) && next;
      $line	=~ /^\s+((\S+))+?\s*$/o;my($file,$l) = $1;
      defined($file) || return (-2, "include", $linenum);
      if($file =~ s/^(\"|\')//o) { $file =~ s/$1$//; }
      open(FILE, $file) || return (-4, "include", $linenum);
      ($_[1] && 040) || syswrite($FO, "${ident}line 0 \"$file\"\n");
      my ($rval, $rmessg, $rlin) = rc_cpp(*FILE, $FO, $ident, ($_[1] | 100));
      ($_[1] && 040) || syswrite($FO, "${ident}line $linenum\n");
      if($rval < 0) { return ($rval, $rmessg, $rlin, $file); }
      else { $lcnt += $rval; } }
    elsif($cmd eq "dnl") {}		#dnl COMMENT
    else { chomp($line); return (-7, "$cmd$line", $linenum); }
  }
  if(defined($_[2])) { %{$_[2]} = %HASH; }	#return hash array
  return $lcnt;
}

##
# (Re)Initialize parser
sub rc_init
{
  undef %OPTIONS;
  %OPTIONS = (
  	'divider'	=> '\s*=\s*',
	'stop_state'	=> undef,
	'comments'	=> ['bash_style'],
	'multivar'	=> 1,
	'noeval'	=> undef,
	'eval_vars'	=> undef,
	'noescape'	=> undef,
	'line_control'	=> '%',
	'sections'	=> '%');
  return 1;
}

##
# Modify parser option
sub rc_set($;$)
{
  defined(%OPTIONS) || rc_init();
  if(exists($OPTIONS{$_[0]})) { return ($OPTIONS{$_[0]} = $_[1]); }
  my($pckg, $fil, $lin)	= caller;
  die("[$fil:$lin] argument error calling rc_set(@_)\n");
  return undef;
}

##
# Start parser sub(FILE, sub(@))
sub rc_parse(\*&)
{
  my($FILE, $line, $slinenum, $linenum, $cfile, $csect);
  $linenum = 0; $FILE	= shift; $cfile='.';

  defined(%OPTIONS) || rc_init();	#autoinit
  while(defined($FILE) && ($line = <$FILE>) && !defined($OPTIONS{'stop_state'}))
  {  $linenum++;$slinenum = 0;		#increment line number
     if($line	=~ /^\s*$/o) { next; }	#ignore empty
     if(defined($OPTIONS{'line_control'}) &&
     	  $line	=~ /^$OPTIONS{'line_control'}line(\s+|$)(\d+)?(\s+\"(\w+)\")?\s*$/)#"
     { $linenum	= $2 || $linenum; defined($4) && ($cfile = $4); next; }
     if(defined($OPTIONS{'sections'}) &&
          $line =~ /^$OPTIONS{'sections'}section(\s+|$)(["'])?(\w+)?\2?\s*$/)#"
     { defined($3) && ($csect = $3); }
     ###At first parse line by quotations (multiline if neccessary)
     my(@parsed);
     while(1)	#loop while somebody does not stop us
     {  if($line	=~ s/^(["'])((\\\1|.)*?)(\1|(\r|\n)+|$)//o) #"#match quoted
	{ if($4 eq $1)	{ push(@parsed, $1.$2); } #found full quoted
	  else		#need look next line (MEMORY EXPENSIVE MODEL)
	  { push(@parsed, $1.$2); $line	= $1;
	    my($quot, $aline) = ($1);$slinenum = $linenum;
	    while(1) #load lines while not found quotation end
	    { $linenum++;
	      $aline = <$FILE>; defined($aline) || last;
 	      $line	.= $aline;	#to be able check EOF
#######
#FIXME: Used lookahead zero-assertion - find better solution (for beter bcompat)
#######
	      if($line =~ s/^(["'])((?:\\.|(?!\1)[^\\])*)\1//o)#"
	      { push(@parsed, pop(@parsed).$2); last; } }
	    defined($aline) || return (-2, $quot, $slinenum, $linenum, $cfile, $csect);
	    chomp($line); } }
	elsif($line	=~ s/^((\\["']|.)+?)(['"]|$)//o 
		|| $line	=~ s/^((\\["']|.)*)$//o)	#"#
        { my($pars, $num3, $comment) = ($1, $3 || ''); 
#FIXME: check
	  (!defined($num3) && $#parsed) && ($pars = pop(@parsed).$pars);
	  sub revers{(length($_[0])?revers(substr($_[0],1)):'').substr($_[0],0,1);}
	  foreach $comment (@{$OPTIONS{"comments"}})	#remove comments
	  { if($comment	=~ /^c_style(\((.+?)(,(.*))?\))?$/o)
	    { my($cm_start, $cm_end, $end) = ($2 || '/*', $4 || revers($2) || '*/');
	      $cm_start =~ s/(.)/\\$1/og; $end = $cm_end; $cm_end =~ s/(.)/\\$1/og;
	      if($pars	=~ s/$cm_start(.*?)($cm_end|$)//g)
	      { if($2 ne $cm_start)	#check wheter whole comment not matched
	        { my($aline) = ($linenum); $num3 = '';$slinenum = $linenum;
		  while(1)	#load lines while not comment end
		  { if(!defined($line))	#will be defined in first loop no more
		    { $linenum++; $aline = <$FILE>;defined($aline) || last;
		       $line = $aline; }
		    if($line =~ s/^(.*?)$cm_end//m)
		    { last; } $line = undef; }
		  defined($aline) || return(-3, $end, $slinenum, $linenum, $cfile, $csect);
	        } } }  #if (c_comment)
	    elsif($comment	=~ /^(bash_style|c\+\+_style)(\((.+)\))?$/o)
	    { my($bash) = ($1 eq 'bash_style') ? '\s' : undef;
	      my($cm_start) = $3 || (($bash) ? '#' : '//');
	      if($pars =~ s/(^|($bash))$cm_start(.*)$//)
	      { $line = $num3 = undef; }
	      if(defined($bash) && defined($2)) { $pars .= $2; }
	      defined($bash) && $pars=~s/\\$cm_start/$cm_start/o;
	      } }  #foreach (@comment)
	  if(defined($pars))
	  { if($num3)	{ push(@parsed, $pars); $line = $num3.$line; }
	    else	{ push(@parsed, $pars);	last; } } }
     }	#while parse out
     #parse vars/lines ; escape ; evalute variable
     my($pos, $tag_pos, @tags, $str, $multi) = (0, 0, undef);
     while(($str = shift(@parsed)))
     { if($pos % 2 == 0) 		#look for plain
       { $str	=~ s/\\(["'])/$1/og;	#"#alter escaped quotes
         while((!$multi || $OPTIONS{"multivar"}) && $str =~ s/^(.*?)$OPTIONS{"divider"}//)
         { $tags[$tag_pos] .= $1; #increment and remove souroundig blanks
	   if($tags[$tag_pos] =~ /^\s*([\S\r\n]+(\s+[\S\r\n]+)*)\s*$/o)
	   { $tags[$tag_pos++] = $1; }
	   $multi = 1; } }
       else				#look for quoted
       { $str	=~ s/\\\'/\'/og;
       	 $str	=~ s/\\(\n|\r)+//o;	#escape backslashed line
         if(substr($str, 0, 1) eq '"')
         { $str	=~ s/\\\"/\"/og;
	   ($OPTIONS{"noeval"}) || ($str = rc_eval($str, $OPTIONS{"eval_vars"}));
           ($OPTIONS{"noescape"})||($str = rc_escape($str)); } 
	  $str	= substr($str, 1); }
       $tags[$tag_pos]	.= $str; $pos++; }
     if(defined($tags[$tag_pos]))
     { if($tags[$tag_pos] =~ /^\s*([\S\r\n]+(\s+[\S\r\n]+)*)\s*$/o)
       { $tags[$tag_pos] = $1; } }
     #call callback function that cares about data storing
     $str = undef; if($#tags != 0) { $str = pop(@tags); }
     while(($pos = shift(@tags)))
     { &{$_[0]}($pos, $str, $slinenum, $linenum, $cfile, $csect); }
  }
  return (!defined($OPTIONS{'stop_state'})) ? 1 :
  		(-1, $OPTIONS{'stop_state'}, $slinenum, $linenum, $cfile, $csect);
}

##
# Stop parser
sub rc_stop(;$)
{
  $OPTIONS{'stop_state'}	= $_[0] || 1;
  return 1;
}

##
# Free parser enviroment
sub rc_free()
{
  undef %OPTIONS;
  return 1;
}

##
# Escape chars in given string sub(string, [additional_escapers])
sub rc_escape($)
{ 
  my(%CNV_TABLE);
  %CNV_TABLE = ('t'=>"\t",'n'=>"\n",'r'=>"\r",'f'=>"\f",'a'=>"\a",'e'=>"\e",'b'=>"\b");
  $_[0] =~ s/\\((\d{1,3})|x([aAbBcCdDeEfF\d]{1,2})|([tnrfbae]))/${ 
  	defined($2) ? \(chr($2)) : defined($3) ? \(chr(hex($3))) : 
		defined($4) ? \$CNV_TABLE{$4} : undef }/go;
  return $_[0];
}

##
# Evalute variables in given string sub(string, [vars])
sub rc_eval($;%)
{ #if variable not defined it is left untached
  $_[0]	=~ s/(\$(\{(.+?)\}|(\w+)))/${ 
  	defined($3) ? (defined($ENV{$3}) ? \$ENV{$3} : \$1) :
  		(defined($ENV{$4}) ? \$ENV{$4} : \$1)}/og;
  return $_[0];
}

1;
