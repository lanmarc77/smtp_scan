#!/usr/bin/perl
use strict;
use DBI;
use IPC::Open3;
use IO::Select;
use Cwd;

my $currentDir = getcwd;
@ENV{'OPENSSL_CONF'}=$currentDir."/openssl.cnf";
$SIG{'PIPE'} = 'IGNORE';
my $dbh = DBI->connect("dbi:SQLite:dbname=scan.sqlite","","");
$dbh->do("PRAGMA auto_vacuum = FULL");
print "Rescan? (YES/n):";my $input=<STDIN>;chomp($input);
if($input eq "YES"){
    dropTables();
    createTables();

    my $sth = $dbh->prepare("SELECT mail FROM email_contacts");
    $sth->execute();
    while (my @row = $sth->fetchrow_array) {
	my ($mail,$mailDomain)=split(/\@/,@row[0]);
	my @mailServer=split(/\n/,`dig \@8.8.8.8 +short $mailDomain MX`);
	if(@mailServer==0){
	    print STDERR "Could not determine mail server for $mailDomain\n";
	}else{
	    foreach(@mailServer){
		my $mailServerEntry=$_;
		if($mailServerEntry=~/(\d+) (.*)\./){
		    my $mailServer=$2;
		    my @mailServerIps=split(/\n/,`dig \@8.8.8.8 +short $mailServer A`);
		    if(@mailServerIps==0){
			print STDERR "Could not determine ipv4 for mail server for $mailServer of domain $mailDomain\n";
		    }else{
			foreach(@mailServerIps){
			    my $ip=$_;
			    my $id=$mailServer." ".$ip;
			    insertScan($id,$mailDomain);
			}
		    }
		}else{
		    print STDERR "Format error for mail server $mailServerEntry of domain $mailDomain\n";
		}
	    }
	}
    }
    $sth->finish();
}
createTables();
print "Starting/resuming to scan\n";
my $sth = $dbh->prepare("SELECT mail_domain,raw_scan_id FROM maildomain_scans");
$sth->execute();
while (my @row = $sth->fetchrow_array) {
    my $mailDomain=@row[0];
    my $id=@row[1];
    my($mailServer,$mailServerIp)=split(/ /,$id);
    if(checkScan($id)==0){
	print "Scanning $mailDomain, $mailServer, $mailServerIp\n";
	my $client_stdout="";
	my $client_stderr="";
	scanMailServer($mailServerIp,$mailServer,\$client_stdout,\$client_stderr);
	saveScan($id,"STDOUT:\n".$client_stdout."\nSTDERR:\n".$client_stderr);
	sleep(10);
    }else{
	print "ALREADY SCANNED THIS MAILSERVER $id\n";
    }
}
$sth->finish();

exit;

sub createTables{
    $dbh->do("CREATE TABLE IF NOT EXISTS raw_scans(id string primary key not null,scan_result text not null)");
    $dbh->do("CREATE TABLE IF NOT EXISTS maildomain_scans(mail_domain string not null,raw_scan_id string not null, primary key(mail_domain,raw_scan_id))");
}

sub dropTables{
    $dbh->do("DROP TABLE IF EXISTS raw_scans");
    $dbh->do("DROP TABLE IF EXISTS maildomain_scans");
    $dbh->do("DROP TABLE IF EXISTS eval_results");
}

sub insertScan{
    my $id=$_[0];
    my $mail_domain=$_[1];
    my $sth=$dbh->prepare("INSERT OR IGNORE INTO maildomain_scans(mail_domain,raw_scan_id) VALUES(?,?)");
    $sth->bind_param( 1, $mail_domain );
    $sth->bind_param( 2, $id );
    $sth->execute();
    $sth->finish();
}

sub saveScan{
    my $id=$_[0];
    my $scan_result=$_[1];
    my $sth=$dbh->prepare("DELETE FROM raw_scans WHERE id=?");
    $sth->bind_param( 1, $id );
    $sth->execute;
    $sth->finish;
    $sth=$dbh->prepare("INSERT INTO raw_scans(id,scan_result) VALUES(?,?)");
    $sth->bind_param( 1, $id );
    $sth->bind_param( 2, $scan_result );
    $sth->execute;
    $sth->finish;
}

sub checkScan{
    my $id=$_[0];
    my $sth=$dbh->prepare("SELECT scan_result FROM raw_scans WHERE id=?");
    $sth->bind_param( 1, $id );
    $sth->execute();
    my @row=$sth->fetchrow_array();
    if( @row ==0 ){
	$sth->finish();
	return 0;
    }
    if(@row[0]!~/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/sg){
	print "Rescan no certificate found\n";
	$sth->finish();
	return 0;
    }
    $sth->finish();
    return 1;
}

sub scanMailServer{
    my $ip=$_[0];
    my $sni=$_[1];
    my $out=$_[2];
    my $err=$_[3];
    my $pid = open3(my $chld_in, my $chld_out, my $chld_err,"timeout 60 openssl s_client -name myiq.de -debug -connect $ip:25 -starttls smtp -showcerts -status -servername $sni");
    my $sel_chld_out = IO::Select->new($chld_out);
    my $sel_chld_err = IO::Select->new($chld_err);
    my $sel_chld_in = IO::Select->new($chld_in);
    my $timeout=0;
    my $state=0;
    while($timeout<10){#10s timeout
        $timeout++;
        while($sel_chld_out->can_read(1)){
            my $buf="";
            my $stat = sysread $chld_out, $buf, 1;
            if($stat==0){
                close($chld_out);
            }else{
                ${$out}.=$buf;
            }
            $timeout=0;
        }
        while($sel_chld_err->can_read(1)){
            my $buf="";
            my $stat = sysread $chld_err, $buf, 1;
            if($stat==0){
                close($chld_err);
            }else{
                ${$err}.=$buf;
            }
            $timeout=0;
        }
        if($state==0){
            if($timeout==3){#after 4s silence
                print $chld_in "EHLO lop\n";
                $state++;
            }
        }elsif($state==1){
            if($timeout==3){#after 4s silence
                print $chld_in "QUIT\n";
                $state++;
            }
        }elsif($state==2){
        }
    }
    waitpid($pid,0);
    return 0;
}
