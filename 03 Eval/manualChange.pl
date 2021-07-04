#!/usr/bin/perl
use strict;
use DBI;
$|=1;
my $dbh = DBI->connect("dbi:SQLite:dbname=scan.sqlite","","");

deleteEntry("mi.sachsen-anhalt.de","mx01.sachsen-anhalt.de 164.133.154.146");
deleteEntry("mi.sachsen-anhalt.de","mx02.sachsen-anhalt.de 164.133.154.147");
change("rostock.de","stadt4.rostock.de 195.37.231.232","ER(0)");

exit;

sub viewScanResult{
    my $id=$_[0];
    my $sth = $dbh->prepare("SELECT scan_result FROM raw_scans WHERE id=?");
    $sth->bind_param( 1, $id );
    $sth->execute();
    my @row=$sth->fetchrow_array();
    if( @row == 0 ){
	$sth->finish();
	return "";
    }
    return @row[0];
}

sub change{
    my $domain=$_[0];
    my $id=$_[1];
    my $flags=$_[2];
    deleteEntry($domain,$id);
    saveNewEntry($domain,$id,$flags);
}

sub deleteEntry{
    my $domain=$_[0];
    my $id=$_[1];
    my $sth = $dbh->prepare("DELETE FROM eval_results WHERE mail_domain=? AND raw_scan_id=?");
    $sth->bind_param( 1, $domain );
    $sth->bind_param( 2, $id );
    $sth->execute();
    $sth-close();
}

sub saveNewEntry{
    my $domain=$_[0];
    my $id=$_[1];
    my $flags=$_[2];
    my $sth = $dbh->prepare("INSERT INTO eval_results(mail_domain,raw_scan_id,flags) VALUES(?,?,?)");
    $sth->bind_param( 1, $domain );
    $sth->bind_param( 2, $id );
    $sth->bind_param( 3, $flags );
    $sth->execute();
    $sth-close();
}
