#!/usr/bin/perl
use strict;
use DBI;
$|=1;
my $dbh = DBI->connect("dbi:SQLite:dbname=scan.sqlite","","");
$dbh->do("PRAGMA auto_vacuum = FULL");
$dbh->do("CREATE TABLE IF NOT EXISTS federal_states (id integer primary key autoincrement,name string not null unique,start_number integer not null,end_number integer no null)");
$dbh->do("CREATE TABLE IF NOT EXISTS electoral_districts (id integer not null unique,name string not null unique,federal_state_id integer not null, primary key(id,name,federal_state_id))");
$dbh->do("CREATE TABLE IF NOT EXISTS email_contacts (electoral_state_id integer,federal_state_id integer,mail string not null,primary key(electoral_state_id,federal_state_id,mail))");

my %bund=(
    "1,11"=>"Schleswig-Holstein",
    "12,17"=>"Mecklenburg-Vorpommern",
    "18,23"=>"Hamburg",
    "24,53"=>"Niedersachsen",
    "54,55"=>"Bremen",
    "56,65"=>"Brandenburg",
    "66,74"=>"Sachsen-Anhalt",
    "75,86"=>"Berlin",
    "87,150"=>"Nordrhein-Westfalen",
    "151,166"=>"Sachsen",
    "167,188"=>"Hessen",
    "189,196"=>"Thüringen",
    "197,211"=>"Rheinland-Pfalz",
    "212,257"=>"Bayern",
    "258,295"=>"Baden-Württemberg",
    "296,299"=>"Saarland"
);

foreach(sort(keys(%bund))){
    my($start,$end)=split(/\,/,$_);
    my $sth=$dbh->prepare("INSERT INTO federal_states(name,start_number,end_number) VALUES(?,?,?)");
    $sth->bind_param( 1, $bund{$_} );
    $sth->bind_param( 2, $start );
    $sth->bind_param( 3, $end );
    $sth->execute();
    $sth->finish();
}

my %bundEmail=(
    "Schleswig-Holstein"=>'wahlen@im.landsh.de',
    "Mecklenburg-Vorpommern"=>'landeswahlleiterin@wahlen.m-v.de',
    "Hamburg"=>'landeswahlamthamburg@bis.hamburg.de',
    "Niedersachsen"=>'landeswahlleitung@mi.niedersachsen.de',
    "Bremen"=>'landeswahlleiter@statistik.bremen.de',
    "Brandenburg"=>'landeswahlleiter@mik.brandenburg.de',
    "Sachsen-Anhalt"=>'lwl@mi.sachsen-anhalt.de',
    "Berlin"=>'landeswahlleitung@wahlen.berlin.de',
    "Nordrhein-Westfalen"=>'landeswahlleiter@im.nrw.de',
    "Sachsen"=>'landeswahlleiter@statistik.sachsen.de',
    "Hessen"=>'wahlen@hmdis.hessen.de',
    "Thüringen"=>'wahlen@statistik.thueringen.de',
    "Rheinland-Pfalz"=>'wahlen@statistik.rlp.de',
    "Bayern"=>'landeswahlleitung@bayern.de',
    "Baden-Württemberg"=>'landeswahlleiter@im.bwl.de',
    "Saarland"=>'landeswahlleiterin@innen.saarland.de'
);

foreach(keys(%bundEmail)){
    my @bundEmails=split(/,/,$bundEmail{$_});
    foreach(@bundEmails){
	my($mail,$domain)=split(/\@/,$_);
	    my @back=`dig +short $domain MX`;
	    if(@back==0){#error no MX entry
		die("No MX entry for $domain\n");
	    }
    }
}

foreach(sort(keys(%bundEmail))){
    my $sth=$dbh->prepare("INSERT INTO email_contacts(federal_state_id,mail,electoral_state_id) VALUES((SELECT id from federal_states WHERE name=?),?,0)");
    $sth->bind_param( 1, $_ );
    $sth->bind_param( 2, $bundEmail{$_} );
    $sth->execute();
    $sth->finish();
}

open(F,"btw21.txt");
my $b="";
my $c="";
while(<F>){
    my $line=$_;
    if($line=~/^(\d\d\d) (.*)\n/){
	if($c eq ""){#first ever wahlkreis
	    $c=$1." ".$2;
	}else{#next wahlkreis
	    my $nc=$1." ".$2;
	    handleElectoralDistrict($c,$b);
	    $c=$nc;
	    $b="";
	}
    }
    if($c ne ""){
	$b.=$line;
    }
}
handleElectoralDistrict($c,$b);


exit;

sub handleElectoralDistrict{
    my $c=$_[0];
    my $b=$_[1];
    my @mailsArray=();
    $b=~s/\r//g;$b=~s/\n//g;#remove all line breaks
    while($b=~/([a-zA-Z]{1}[äüöÄÜÖa-zA-Z0-9_\.-]*?)\@([äüöÄÜÖa-zA-Z0-9_\.-]+\.[a-z]{2,10})/sg){#find an email
	my $mail=substitudeMail($1);;
	my $domain=substitudeDomain($2);
	my @back=`dig +short $domain MX`;
	if(@back!=0){#the domain has an MX entry
	    push @mailsArray,$mail."\@".$domain;
	}else{#no mx found for domain
	    print STDERR "Error for $domain\n";
	}
    }
    if(@mailsArray==0){
	die("No Emails found for $c");
    }
    if($c!~/(\d+) (.*)/){
	die("ERROR for $c");
    }
    my ($id,$electoralDistrictName)=($1,$2);
    $id=int($id);
    my $sth=$dbh->prepare("INSERT INTO electoral_districts(id,name,federal_state_id) VALUES(?,?,(SELECT id from federal_states WHERE start_number<=? and end_number>=?))");
    $sth->bind_param( 1, $id );
    $sth->bind_param( 2, $electoralDistrictName );
    $sth->bind_param( 3, $id );
    $sth->bind_param( 4, $id );
    $sth->execute();
    $sth->finish();
    foreach(@mailsArray){
	$sth=$dbh->prepare("INSERT INTO email_contacts(electoral_state_id,mail,federal_state_id) VALUES(?,?,0)");
	$sth->bind_param( 1, $id );
	$sth->bind_param( 2, $_ );
	$sth->execute();
	$sth->finish();
    }
}
sub substitudeMail{
    my $m=$_[0];
    $m=~s/ü/ue/g;
    $m=~s/Ü/ue/g;
    $m=~s/ö/oe/g;
    $m=~s/Ö/oe/g;
    $m=~s/ä/ae/g;
    $m=~s/Ä/ae/g;
    return $m;
}

sub substitudeDomain{
    my $origName=$_[0];
    my %substMatrix=(
	"schleswigflensburg.de"=>"schleswig-flensburg.de",
	"hamburgmitte.hamburg.de"=>"hamburg-mitte.hamburg.de",
	"hamburgnord.hamburg.de"=>"hamburg-nord.hamburg.de",
	"potsdammittelmark.de"=>"potsdam-mittelmark.de",
	"bezirksamtneukoelln.de"=>"bezirksamt-neukoelln.de",
	"staedteregionaachen.de"=>"staedteregion-aachen.de",
	"kreiseuskirchen.de"=>"kreis-euskirchen.de",
	"kreis-re.dej.esser"=>"kreis-re.de",
	"landkreismittelsachsen.de"=>"landkreis-mittelsachsen.de",
	"llkwafkb.de"=>"lkwafkb.de",
	"werra-meissnerkreis.de"=>"werra-meissner-kreis.de",
	"schwalm-ederkreis.de"=>"schwalm-eder-kreis.de",
	"lahn-dillkreis.de"=>"lahn-dill-kreis.de",
	"kreisbergstrasse.de"=>"kreis-bergstrasse.de",
	"ahrweiler.de"=>"kreis-ahrweiler.de",
	"cohem-zell.de"=>"cochem-zell.de",
	"tirier-saarburg.de"=>"trier-saarburg.de",
	"stadt-mainz.de"=>"stadt.mainz.de",
	"LRAaoe.de"=>"LRA-aoe.de",
	"lra-starnberg.bayern.de"=>"lra-starnberg.de",
	"landratsamtheilbronn.de"=>"landratsamt-heilbronn.de",
	"neckar-odenwaldkreis.de"=>"neckar-odenwald-kreis.de",
	"neckarodenwald-kreis.de"=>"neckar-odenwald-kreis.de",
	"saarpfalzkreis.de"=>"saarpfalz-kreis.de",
	"charlottenburgwilmersdorf.de" => "charlottenburg-wilmersdorf.de",
	"rhein-neckarkreis.de" => "rhein-neckar-kreis.de",
	"rheinkreis-neuss.de" => "rhein-kreis-neuss.de",
	"kreiscoesfeld.de" => "kreis-coesfeld.de",
	"stadthagen.de" => "stadt-hagen.de",
	"landkreisfulda.de" => "landkreis-fulda.de",
	"rheingautaunus.de" => "rheingau-taunus.de",
	"cochemzell.de" => "cochem-zell.de"
    );
    foreach(keys(%substMatrix)){
	if($_ eq $origName){
	    return $substMatrix{$_};
	}
    }
    return $origName;
}
