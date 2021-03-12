#!/usr/bin/env perl

################################################################
# Warning: Only use against targets that you have consent with #
################################################################

#####
#TODO: 
#   Add dynamic parameter gathering to increase effectiveness of input validation tests
#   Fix the output saving to include timestamps to the file name
#   Increase list of terms for spidering and sub-domain enumeration
#   Fix some typos and grammatical errors
#   Fix encoding test be more accurate and minimize testing
#   Make it so that the suppress option automatically enabled logging
#   Add in code recomendations (ie. Recommend a useful robots.txt file)
#   Expand list of terms for CMS identification and add new CMS'
#   Expand upon SPF recommendations
#   Update function
#####
#FIXED/ADDED:
#   1.4 (QOL updates)
#   Minor bug fixes
#   Added 2 new spider terms
#   Will now clear screen when running
#   Added more comments for easier code understanding (more are needed)#   
#####
#   1.3
#   This changelog since I never had it in before (will track changes from here on out)
#   Added SQL error testing for MySQL to test for SQLi
#   Added a ping check to determine if the target is live
#   Cleaned up the code a bit
#   IP testing added in addition to basic domain names
#   Ability to use "offline" tests if IP address is passed
#   Minor bug fixes
#   Removed unused variables
#####

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
system("clear");

#Checking user input
my (%options, $dbg, $sup);
GetOptions (\%options, "domain:s", "save", "suppress");
die "Usage: perl $0 [options]\n--domain=\"<target domain name>\"\t(REQUIRED)\n--save\tStores the output to a log file (OPTIONAL)\n--suppress\tDoes not display any output (OPTIONAL)\n" if((!keys %options) or (!exists $options{domain}));

#Slick Banner
&banner;

#Checks if the saving option is enabled
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

#Assigns variables and does initial site check
my $site = $options{domain};
my $skip = ip_skip_check($site);
connection_test($site);

###############

my ($b, $wi, $em, $spf, $pages, $subs, $robo, $frame, $filtered, $sql);
#Processing the code

if($skip == 1){
    print "-----\n[!] Gathering information..\n[!] Target domain is IP address.. skipping web searches...\n-----";
    $b = &bot;
    $pages = basic_spider($site, $b);
    $subs = sub_domain($site, $b);
    $robo = robot_txt($site, $b);
    $frame = cms_fingerprint($site, $b);
    $filtered = sanitation_check($site, $b);
    $sql = sql_errors($site, $b);
}

if($skip == 0){
    print "-----\n[!] Gathering information.. please wait...\n-----\n";
    $b = &bot;
    $wi = website_information($site);
    $em = email_mine($site, $b);
    $spf = spf_validate($site);
    $pages = basic_spider($site, $b);
    $subs = sub_domain($site, $b);
    $robo = robot_txt($site, $b);
    $frame = cms_fingerprint($site, $b);
    $filtered = sanitation_check($site, $b);
    $sql = sql_errors($site, $b);
}

#Output
if(!defined $sup){
    print "$wi\n";
    print "$em\n";
    print "$spf\n";
    print "$pages\n";
    print "$subs\n";
    print "$robo\n";
    print "$frame\n";
    print "$filtered\n";
    print "$sql\n";
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
    save_to_log($filtered);
    save_to_log($sql);
}

############
#Core functions
############

#Done
sub connection_test {
    my $t = shift;
    my $ping = `ping -c 1 $t`; #sends 1 ping packet to test if site is alive
    if($ping) {
        print "{+} Connection to the website is active\n\n";
        return
    }else{
        die "{!} Unable to connect to website.... exiting\n";
    }
}

#Done
sub ip_skip_check {
    my $ip = shift;
    if ($ip =~ /(?:\d{1,3}\.?)+/gis){ #regex used for testing if passed domain is IP address
        return 1;
    } else {
        return 0;
    }
}

#Done
sub get_info {
    my ($d, $browser) = @_;
    my @dig = `dig +short $d`; #gets just the IP address from the 'dig' command
    my ($ip, $status, $server, $powered);
    for (@dig) {
        chomp($_);
        $ip .= " $_,";         
    }
    my $res = $browser->head("https://$d"); #sends a HEAD request for data parsing
    if ($res->is_success){
        $status = $res->status_line;
    }else{
        warn "{!} Unable to send HEAD request\n";
    }
    my @headers = split(/\n/, $res->as_string); #splite up the response by newlines
    for (@headers) {
        if ($_ =~ m/Server: (.*)/g){
            $server = $1;
        }elsif ($_ =~ m/X-Powered-By: (.*)/g){
            $powered .= "$1, ";
        }
    }
    #removes trailing ','
    $powered = substr($powered, 0, -2);
    $ip = substr($ip, 0, -1);
    return($ip, $status, $server, $powered);
}

#Done
sub get_nameserver {
    my $i = shift;
    my ($lookup, $netrange, $cidr, $netname, $orgname);
    $lookup = `whois $i`; #whois request
    if($lookup =~ m/netrange:\s*((?:\d{1,3}[\.\s]+)+\s*\-\s*(?:\d{1,3}[\.\s]+)+)\s*cidr:\s*((?:\d{1,3}[\.\s]+)+\d+\/\d+)\s*netname:\s*([\w\-]+)\s*\w+.{0,1050}?orgname:\s*([\w\s]+)(?=orgid)/gis){ #regex for parsing whois response
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
    {+} DNS INFO: \n\t{+} Netrange: $dns[0]\n\t{+} CIDR: $dns[1]\n\t{+} Netname: $dns[2]\n\t{+} Orgname: $dns[3]";
    return $info;
}

#Done
sub email_mine {
    my ($e, $bot) = @_;
    my (@emails, %mail, $email, @found);
    my $url = 'https://www.google.com/search?num=100&start=0&h1=en&meta=&q=%40%22'.$e.'%22'; #queries Google for email addresses to avoid unneeded requests to website
    my $res = $bot->get($url);
	if($res -> is_success) {
		@emails = $res->as_string =~ m/[a-z0-9_.-]+\@/ig; #saves potential email addresses to an array based on regex matching
		foreach $email (@emails) {
			if(!exists $mail{$email}) {
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
    #digs for TXT records, then regex match for SPF records 
    my $find = `dig $s txt`;
    if ($find =~ /(v=spf.*)/g){
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
    my @basic = qw(contact about pricing blog admin adminstration wp-admin login feed about-us search-results results login.php connect.php);
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

#Done
sub sub_domain {
    my ($s, $b) = @_;
    my @subs = qw(blog www shop members secure app);
    my @found_subs;
    for (@subs) {
        my $url = "http://$_.$s";
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
    my $robot = $b -> get("http://$r/robots.txt");
    my $rfile;
    my $bot_file = "===========[ROBOTS]===========\n";
    if($robot -> is_success) {
        $rfile = $robot -> decoded_content;
    } else {
        $rfile = "{!} NOT FOUND\n{!} Malicious Bots may attack the website\n";
        $bot_file .= $rfile;
        return $bot_file;
    }
    
    if($rfile){
        $bot_file .= "{!} ROBOTS.TXT:\n$rfile\n";
    }
    return $bot_file;
}

#Done
sub cms_fingerprint {
    my ($g, $b) = @_;
    my $get = $b->get("http://$g");
    my $cms;
    my @wp = qw(wp-content wordpress wp-includes);
    my @joom = qw(modules components);
    my $fw = "===========[FRAMEWORK IDENTIFICATION]===========\n";
    if($get->is_success) {
        my $content = $get->as_string;
        my @page = split(/\n/, $content);
        for my $p(@page){
            for my $w (@wp){
                if ($p =~ /$w/gis){
                    $cms = "wordpress";
                    $fw .= "{!} DETECTED FRAMEWORK: $cms\n{!} Recommend using 'WPScan' for further analysis\n";
                    return($fw);
                }
            }
        }
        for my $p(@page){
            for my $j (@joom) {
                if ($p =~ /$j/gis){
                    $cms = "joomla";
                    $fw .= "{!} DETECTED FRAMEWORK: $cms\n{!} Recommen using 'JoomScan' for further analysis\n";
                    return($fw);
                }
            }
        }
    }
    $cms = "Custom/Unknown";
    $fw .= "{!} DETECTED FRAMEWORK: $cms\n";
    return($fw);
}

#Done
sub sanitation_check {
    my ($s, $b) = @_;
    my $test = "===========[INPUT SANITATION CHECK]===========\n";
    my @html = qw(< > " ' /);
    my %encoded = qw(
        < %3C
        > %3E
        " %22
        ' %27
        / %2F
    );
    my (%matching);

    while(my ($k, $v) = each %encoded){
        for my $h (@html){
            my $htest = $b -> get("http://$s/?s=$h");
            if($htest -> is_success){
                my $base = $htest -> base;
                if($base =~ m/^https?:\/\/.*?\/\?\w+=(.*)/g){
                    my $q = $1;
                    if($v eq $q){
                        $matching{$k}=$v;
                    }
                }
            }
        }
    }
    
    while (my ($nk, $nv) = each %matching){
        $test .= "[+] $nk is being filtered to $nv, sanitation appears to work\n";
    }
    $test .= "{!} More aggressive testing potentially needed\n";
    return $test;
}

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
sub sql_errors {
    my ($s, $b) = @_;
    my @sql_tests = ("/?q=1", "/?q=1'", "/?q=1\"", "/?q=[1]", "/?q[]=1", "/?q=1`", "/?q=1\\", "/?q=1/*'*/", "/?q=1/*!1111'*/", "/?q=1'||'asd'||'", "/?q=1' or '1'='1", "/?q=1 or 1=1", "/?q='or''='");

    my $sql_rez = "===========[DATABASE SECURITY CHECK]===========\n";

    for my $sql(@sql_tests){
        my $page = "http://$s$sql";
        my $c = $b -> get($page);
        if($c -> is_success){
            my $html = $c ->decoded_content;
            if($html =~ /.*error.*SQL\s*syntax/gis){
                $sql_rez .= "[+] SQL Injection found at $page\n";
            }
        }
    }
    $sql_rez .= "[+] SQL Injection not found\n";
    return $sql_rez;
}

#Done
sub banner {
    my $version = "1.4";
    my $banner = << "EOB";
    ########################################
    #\tGeneral Purpose Website Auditing   #
    #\tVersion: $version                       #
    ########################################
EOB

    print "$banner\n";
}


