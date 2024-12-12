#!/usr/bin/perl

open(FD, "/usr/sbin/uurate @ARGV|") || die("uutraf: starting uurate: $!\n");

while(<FD>) {
  if(/^(Compact summary|\(I\))/) {
	print "\n";
	$ok = 1;
  }
  next if (!$ok);
  print;
}
close(FD);
