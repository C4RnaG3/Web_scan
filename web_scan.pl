#!/usr/bin/perl

################################################################
# Warning: Only use against targets that you have consent with #
################################################################

#Imported modules
use strict;
use warnings;
use Data::Dumper qw(Dumper);
use Getopt::Long;
use constant SCAN_LOG => "log.txt";
use LWP::UserAgent;
use LWP::Protocol::https;
use HTTP::Cookies;
no warnings 'uninitialized';
$| = 1;

#Checking user input
my (%options, $dbg, $sup);
GetOptions (\%options, "domain:s", "save", "suppress");
die "Usage: perl $0 [options]\n--domain=\"<tagerget domain name>\"\t(REQUIRED)\n--save\tStores the output to a log file (OPTIONAL)\n--suppress\tDoes not display any output (OPTIONAL)\n" if((!keys %options) or (!exists $options{domain}));

#Slick Banner
&banner;

#Checks for additional parameters
if(exists $options{save}){
    $dbg = 1;
    if(-e SCAN_LOG){
        my $time = localtime();
        my $time_stamp = "[!] Scan ran at: $time\n";
        print "-----\n[!] Current scan log exists (".SCAN_LOG.")... overwriting...\n-----\n";
        open(my $fh, '>', SCAN_LOG);
        print $fh $time_stamp;
        close($fh);
    }
}

if(exists $options{suppress}){
    $sup = 1;
}
######

#Processing the code
print "-----\n[!] Gathering information.. please wait...\n-----\n";
my $b = &bot;
my $wi = website_information($options{domain});
my $em = email_mine($options{domain}, $b);
my $spf = spf_validate($options{domain});
my $pages = basic_spider($options{domain}, $b);
my $subs = sub_domain($options{domain}, $b);
my $robo = robot_txt($options{domain}, $b);
my $frame = cms_fingerprint($options{domain}, $b);

#Output
if(!defined $sup){
print "$wi\n";
print "$em\n";
print "$spf\n";
print "$pages\n";
print "$subs\n";
print "$robo\n";
print "$frame\n";
}

#Save outputs to the log; Could probably clean this up a bit
if($dbg){
    save_to_log($wi);
    save_to_log($em);
    save_to_log($spf);
    save_to_log($pages);
    save_to_log($subs);
    save_to_log($robo);
    save_to_log($frame);
}

############
#Core functions
############

#Done
sub get_info {
    my ($d, $browser) = @_;
    my @dig = `dig +short $d`;
    my ($ip, $status, $server, $powered);
    for (@dig) {
        chomp($_);
        $ip .= " $_,";         
    }
    my $res = $browser->head("https://$d");
    if ($res->is_success){
        $status = $res->status_line;
    }else{
        die "{!} Unable to successfully reach target\n";
    }
    my @headers = split(/\n/, $res->as_string);
    for (@headers) {
        if ($_ =~ m/Server: (.*)/g){
            $server = $1;
        }elsif ($_ =~ m/X-Powered-By: (.*)/g){
            $powered .= "$1, ";
        }
    }
    $powered = substr($powered, 0, -2);
    $ip = substr($ip, 0, -1);
    return($ip, $status, $server, $powered);
}

#Done
sub get_nameserver {
    my $i = shift;
    my ($lookup, $netrange, $cidr, $netname, $orgname);
    $lookup = `whois $i`;
    if($lookup =~ m/netrange:\s*((?:\d{1,3}[\.\s]+)+\s*\-\s*(?:\d{1,3}[\.\s]+)+)\s*cidr:\s*((?:\d{1,3}[\.\s]+)+\d+\/\d+)\s*netname:\s*([\w\-]+)\s*\w+.{0,1050}?orgname:\s*([\w\s]+)(?=orgid)/gis){
        $netrange = $1;
        $cidr = $2;
        $netname = $3;
        $orgname = $4;
    }
    return($netrange, $cidr, $netname, $orgname);
}

#Done
sub website_information {
    my $domain = shift;
    my @info = get_info($domain, $b);
    my @dns = get_nameserver($info[0]);
    my $info ="===========[WEBSITE INFORMATION]===========
    {+} DOMAIN: $domain
    {+} SITE IP/s: $info[0]
    {+} STATUS CODE: $info[1]
    {+} SERVER TECHNOLOGY: $info[2], $info[3]
    {+} DNS INFO: \n\t{+} Netrange: $dns[0]\t{+} CIDR: $dns[1]\n\t{+} Netname: $dns[2]\n\t{+} Orgname: $dns[3]";
    return $info;
}

#Done
sub email_mine {
    my ($e, $bot) = @_;
    my (@emails, %mail, $email, @found);
    my $url = 'https://www.google.com/search?num=100&start=0&h1=en&meta=&q=%40%22'.$e.'%22';
    my $res = $bot->get($url);
	if($res -> is_success) {
		@emails = $res->as_string =~ m/[a-z0-9_.-]+\@/ig;
		foreach $email (@emails) {
			if(not exists $mail{$email}) {
				push @found, $email.$e;
				$mail{$email} = 1; 
			}
		}
	}
    my $rese = "===========[E-Mail addresses]===========\n";
    if(scalar @found == 0){
        $rese .= "{!} NO EMAILS FOUND\n";
    }else{
        for (@found){
            $rese .= "{!} Possible email match: $_\n";
        }
    }
    return $rese;
}

#Done
sub spf_validate {
    my $s = shift;
    my $find = `dig $s txt`;
    if ($find =~ m/(v=spf.*)/g){
        my $res = "===========[SPF RECORD]===========\n";
        if($1) {
            $res .= "{!} Found Record:\n$1\n";
        }else{
            $res .= "{!} NO SPF RECORD FOUND, EMAIL SPOOFING POSSIBLE\n";
        }
        return $res;
    }
}

#Done
sub basic_spider {
    my ($d, $b) = @_;
    my @basic = qw(contact about pricing blog admin adminstration wp-admin login feed about-us);
    my @found;
    for (@basic) {
        my $page = "https://$d/$_";
        my $res = $b->get($page);
        if($res -> is_success) {
            push @found, $page;
        }
    }
    my $spider = "===========[BASIC SPIDER RESULTS]===========\n";
    if(scalar @found == 0) {
        $spider .= "{!} NO PAGES FOUND\n";
    }else{
        for(@found){
            $spider .= "{+} FOUND PAGES: $_\n";
        }
    }
    return($spider);
}

#Done; Could be expanded on
sub sub_domain {
    my ($s, $b) = @_;
    my @subs = qw(blog www shop members secure app);
    my @found_subs;
    for (@subs) {
        my $url = "https://$_.$s";
        my $subdomain = $b -> get($url);
        if($subdomain -> is_success) {
            push @found_subs, $url;
        }
    }
    my $sd = "===========[BASIC SUB-DOMAIN ENUMERATION]===========\n";
    if (scalar @found_subs == 0) {
        $sd .= "{!} NO SUB-DOMAINS FOUND\n";
    } else {
        for(@found_subs){
            $sd .= "{+} FOUND SUB-DOMAINS: $_\n";
        }
    }
    return $sd;
}

#Done
sub robot_txt {
    my ($r, $b) = @_;
    my $robot = $b -> get("https://$r/robots.txt");
    my $rfile;
    if($robot -> is_success) {
        $rfile = $robot -> decoded_content;
    } else {
        $rfile = "NOT FOUND\n";
        return $robot;
    }
    my $bot_file = "===========[ROBOTS]===========\n";
    if($rfile){
        $bot_file .= "{!} ROBOTS.TXT:\n$rfile\n";
    }
    return $bot_file;
}

#Done; Could be expanded on
sub cms_fingerprint {
    my ($g, $b) = @_;
    my $get = $b->get("https://$g");
    my $cms;
    my @wp = qw(wp-content wordpress);
    my @joom = qw(modules components);
    if($get->is_success) {
        my $content = $get->as_string;
        for(@wp){
            if ($_ = grep(/\Q$content\E/, @wp)){
                $cms = "wordpress";
            }
        }
        for(@joom) {
            if ($_ = grep(/\Q$content\E/, @joom)){
                $cms = "joomla";
            }
        }
    }
    $cms = "Custom/Unknown";
    my $fw = "===========[FRAMEWORK IDENTIFICATION]===========\n";
    $fw .= "{!} DETECTED FRAMEWORK: $cms\n";
    return($fw);
}

#Needs to be built
sub vuln_test_sanitation {}

#####
#Utility functions
#####

#Done
sub bot {
	my $cookies = HTTP::Cookies->new;
	my $bot = LWP::UserAgent -> new;
	$bot->agent('Mozilla/4.76 [en] (Win98; U)');
	$bot -> cookie_jar($cookies);
	$bot -> timeout(10);
	#$bot ->show_progress(1);
	return $bot;
}

#Done
sub save_to_log {
    my $log = shift;
    open(my $fh, '>>', SCAN_LOG) || die $!;
    print $fh $log;
    print $fh "\n";
    close $fh;   
}

#Done
sub banner {
    my $version = "0.5";
    my $banner = << "EOB";
    ########################################
    #\tGeneral Purpose Website Auditing   #
    #\tVersion: $version                       #
    ########################################
EOB

    print "$banner\n";
}

sub report {}
