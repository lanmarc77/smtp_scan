#!/usr/bin/perl
use strict;
use DBI;
$|=1;
my $dbh = DBI->connect("dbi:SQLite:dbname=scan.sqlite","","");
$dbh->do("PRAGMA auto_vacuum = FULL");
my $sth = $dbh->prepare("SELECT mail_domain,raw_scan_id,flags FROM eval_results");
$sth->execute();
#eval_results (mail_domain string not null,raw_scan_id string not null ,flags string not null,primary key(mail_domain,raw_scan_id));
while (my @row = $sth->fetchrow_array) {
    my($mailDomain,$scanId,$flags)=@row;
    print $mailDomain."|".$scanId."|".$flags."\r\n";
}
$sth->finish();


exit;