#!/usr/bin/perl
use strict;
use IPC::Open3;
use DBI;
$|=1;
my %affectedMailDomains=();
my $dbh = DBI->connect("dbi:SQLite:dbname=scan.sqlite","","");
$dbh->do("PRAGMA auto_vacuum = FULL");
$dbh->do("DROP TABLE IF EXISTS eval_results");
$dbh->do("CREATE TABLE IF NOT EXISTS eval_results (mail_domain string not null,raw_scan_id string not null ,flags string not null,primary key(mail_domain,raw_scan_id))");
my $sth = $dbh->prepare("SELECT mail_domain,raw_scan_id,scan_result FROM maildomain_scans JOIN raw_scans ON id=raw_scan_id");
$sth->execute();

while (my @row = $sth->fetchrow_array) {
    my($mailDomain,$scanId,$scanResult)=@row;
    print $scanId."\n";
    my $flags="";
    if($scanResult =~ /\nCONNECTED\(00000003\)\n/){
	if($scanResult=~/\nno peer certificate available\n/){
	    $flags=addFlag($flags,"ER(1)");
	}else{
	    my ($hostname, $ip)=split(/ /,$scanId);
	    my @certChain=getCertificateChain($scanResult);
	    my $h=-1;
	    foreach my $cert(@certChain){
		if(verifyCertificateHostname($cert,$hostname)==0){
		    $h=0;
		    last;
		}
	    }
	    if($h!=0){
		$flags=addFlag($flags,"HN");
	    }
	    my $e=checkCertificateExpiry(@certChain[0]);
	    if($e==1){
		my $date=getExpiryDate(@certChain[0]);
		$flags=addFlag($flags,"EX($date)");
	    }
	    my $l=checkCertificateExpiry(@certChain[0],int(31536000*4));
	    if($l==0){
		my $date=getExpiryDate(@certChain[0]);
		$flags=addFlag($flags,"LO($date)");
	    }

	    my $s=checkSelfSignedCertificate($scanResult);
	    if($s==1){
		$flags=addFlag($flags,"SS");
	    }
	    my $v=checkCertificateVerify($scanResult);
	    if($v==0){
		$flags=addFlag($flags,"VE(".@certChain.")");
	    }
#country check not used
#	    my $c=checkCountryWhois($ip);
#	    my $c2=checkCountry($ip);
#	    if($c ne $c2){
#		print "$mailDomain $scanId: CT($c,$c2)\n";
#		#$flags=addFlag($flags,"CT($c,$c2)");
#	    }elsif($c ne "DE"){
#		print "$mailDomain $scanId: CT($c)\n";
#		#$flags=addFlag($flags,"CT($c)");
#	    }
	    my($tls_version,$cipher)=split(/ /,getConnectionInfo($scanResult));
	    if($tls_version ne ""){
		$flags=addFlag($flags,"TS($tls_version)");
		$flags=addFlag($flags,"CS($cipher)");
	    }

	    my($bits,$hash)=split(/ /,getCertificateBitsAndHash(@certChain[0]));
	    if((($bits ne "")&&($bits<2048))||($bits eq "")){
		$flags=addFlag($flags,"CB($bits)");
	    }
	    if($hash !~ /sha256WithRSAEncryption/i){
		$flags=addFlag($flags,"HS($hash)");
	    }
	}
    }else{
	$flags=addFlag($flags,"ER(0)");
    }
    if($flags ne ""){
	print "$mailDomain $scanId: ".$flags."\n";
	saveEval($scanId,$flags,$mailDomain);
	$affectedMailDomains{$mailDomain}=1;
    }
}
exit;

sub getCertificateChain{
    my $scan=$_[0];
    my @certs=();
    while($scan=~/(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)/sg){
	push @certs,$1;
    }
    return @certs;
}

sub checkCertificateExpiry{
    my $cert=$_[0];
    my $rt=$_[1];
    if ($rt eq ""){
	$rt=0;
    }
    if($cert eq ""){
	return 0;
    }
    my $pid = open3(my $chld_in, my $chld_out, my $chld_error, "openssl x509 -in - -checkend $rt -nocert")
    or die "open3() failed $!";
    my $r;
    print $chld_in $cert;
    close($chld_in);
    waitpid( $pid, 0 );
    my $child_exit_status = $? >> 8;
    if($child_exit_status==1){
	return 1;
    }
    return 0;
}

sub checkCertificateVerify{
    my $scan=$_[0];
    if($scan =~ /\nVerification: OK\n/){
	return 1;
    }
    return 0;
}

sub checkSelfSignedCertificate{
    my $scan=$_[0];
    if($scan =~ /Verification error: self signed certificate/){
	return 1;
    }
    return 0;
}

sub getConnectionInfo{
    my $scan=$_[0];
    if($scan =~ /New, (.*?), Cipher is (.*?)\n/){
	my $tls_version=$1;
	my $cipher=$2;
	if($scan=~/Secure Renegotiation IS supported\n/){
	    if($scan=~/Protocol.*?\: (.*?)\n.*?Cipher.*?\: (.*?)\n/){
		$tls_version=$tls_version."->".$1;
		$cipher=$cipher."->".$2;
	    }else{
		return "?? ??";
	    }
	}
	if(($tls_version !~ /TLSv1.2/)&&($tls_version !~ /TLSv1.3/)){
	    return $tls_version." ".$cipher;
	}
    }else{
	return "?? ??";
    }
    return "";
}

sub getExpiryDate{
    my $cert=$_[0];
    if($cert eq ""){
	return "";
    }
    my $pid = open3(my $chld_in, my $chld_out, my $chld_error, "openssl x509 -in - -enddate -nocert")
    or die "open3() failed $!";
    my $r;
    print $chld_in $cert;
    close($chld_in);
    my $response="";
    while(<$chld_out>){
	$response.=$_;
    }
    if($response=~/notAfter=(.*)/){
	return $1;
    }
    return $response;
}

sub checkCountry{
    my $ip=$_[0];
    my $back=`geoiplookup $ip`;
    if($back=~/.*?: (.*?),.*\n/){
	return uc($1);
    }
    return "??";
}

sub checkCountryWhois{
    my $ip=$_[0];
    my $back=`whois $ip|grep country`;
    if($back=~/country:\s+(.*?)\n/){
	return uc($1);
    }
    return "??";
}

sub verifyCertificateHostname{
    my $cert=$_[0];
    my $hostname=$_[1];
    if($cert eq ""){
	return 3;
    }
    my $pid = open3(my $chld_in, my $chld_out, my $chld_error, "openssl x509 -in - -checkhost $hostname -nocert")
    or die "open3() failed $!";
    my $r;
    print $chld_in $cert;
    close($chld_in);
    my $response="";
    while(<$chld_out>){
	$response.=$_;
    }
    if($response=~/Hostname $hostname does match certificate/sg){
	return 0;
    }
    if($response=~/Hostname $hostname does NOT match certificate/sg){
	return 1;
    }
    die("BUG verifyCertificateHostname $response $cert");
}

sub getCertificateBitsAndHash{
    my $cert=$_[0];
    my $bits=0;
    my $hash="";
    if($cert eq ""){
	return "";
    }
    my $pid = open3(my $chld_in, my $chld_out, my $chld_error, "openssl x509 -in - -text -nocert 2>/dev/null")
    or die "open3() failed $!";
    my $r;
    print $chld_in $cert;
    close($chld_in);
    my $response="";
    while(<$chld_out>){
	$response.=$_;
    }
    if($response=~/Key\:.*?(\d+) bit.*?\n/sg){
	$bits=$1;
    }else{
	print STDERR "Error determining certificates bit size $response\n";
	exit;
    }
    if($response=~/Signature Algorithm: (.*?)\n/sg){
	$hash=$1;
    }else{
	print STDERR "Error determining certificates hash\n";
	exit;
    }
    return $bits." ".$hash;
}

sub addFlag{
    my $currentFlags=$_[0];
    my $newFlag=$_[1];
    if($currentFlags eq ""){
	return $newFlag;
    }
    return $currentFlags.";".$newFlag;
}


sub saveEval{
    my $scan_id=$_[0];
    my $flags=$_[1];
    my $mail_domain=$_[2];
    my $sth=$dbh->prepare("INSERT INTO eval_results(raw_scan_id,mail_domain,flags) VALUES(?,?,?)");
    $sth->bind_param( 1, $scan_id );
    $sth->bind_param( 2, $mail_domain );
    $sth->bind_param( 3, $flags );
    $sth->execute;
    $sth->finish;
}
