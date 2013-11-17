use strict;

package Plugins::ShairTunes::Plugin;

use base qw(Slim::Plugin::OPMLBased);

use Digest::MD5 qw(md5 md5_hex);
use MIME::Base64;
use Slim::Utils::Log;
use Slim::Utils::Prefs;
use IO::Socket::INET6;
use Crypt::OpenSSL::RSA;
use Net::SDP;
use IPC::Open2;

use Plugins::ShairTunes::AIRPLAY;

# create log categogy before loading other modules
my $log = Slim::Utils::Log->addLogCategory({
	'category'     => 'plugin.shairtunes',
#	'defaultLevel' => 'ERROR',
	'defaultLevel' => 'INFO',
	'description'  => getDisplayName(),
});


use Slim::Utils::Misc;
my $prefs = preferences('plugin.shairtunes');

my $airport_pem = join '', <DATA>;
my $rsa = Crypt::OpenSSL::RSA->new_private_key($airport_pem) || die "RSA private key import failed";

my $hairtunes_cli = "hairtunes";
my $pipepath = "/tmp/pipe";

my %clients = ();
my %sockets = ();
my %players = ();
my %connections = ();

sub initPlugin 
{
	my $class = shift;

	$log->info("Initialising " . $class->_pluginDataFor('version'));

        # Subscribe to player connect/disconnect messages
        Slim::Control::Request::subscribe(
                \&playerSubscriptionChange,
                [['client'],['new','reconnect','disconnect']]
        );

#	Slim::Control::Request::subscribe( \&pauseCallback, [['pause']] );

	return 1;
}

sub playerSubscriptionChange {
	my $request = shift;
	my $client  = $request->client;
	
	my $reqstr = $request->getRequestString();
	my $clientname = $client->name();

	$log->debug("request=$reqstr client=$clientname");
	
	if ($reqstr eq "client new") {
	        $sockets{$client} = createListenPort();
	        $players{$sockets{$client}} = $client;

                if ($sockets{$client}) {
                        # Add us to the select loop so we get notified
                        Slim::Networking::Select::addRead($sockets{$client}, \&handleSocketConnect);
                
                        $clients{$client} = publishPlayer($clientname, "", $sockets{$client}->sockport());
                } else {
                        $log->error("could not create ShairTunes socket for $clientname");
                        delete $sockets{$client}
                }
	}
}


sub shutdownPlugin 
{
#	Slim::Control::Request::unsubscribe(\&pauseCallback);
 	return;
}

sub getDisplayName() 
{ 
	return('PLUGIN_SHAIRTUNES')
}


sub createListenPort()
{
    my $port = 5123;
    my $listen;

    $listen   = new IO::Socket::INET6(Listen => 1,
                        Domain => AF_INET6,
                        ReuseAddr => 1,
                        Proto => 'tcp' );

    $listen ||= new IO::Socket::INET(Listen => 1,
                        ReuseAddr => 1,
                        Proto => 'tcp' );

    return $listen
}

sub publishPlayer()
{
	my ($apname, $password, $port) = @_;

	my $pid = fork();
        
	my $pw_clause = (length $password) ? "pw=true" : "pw=false";
	my @hw_addr = +(map(ord, split(//, md5($apname))))[0..5];

        if ($pid==0) {
            { exec 'avahi-publish-service',
                join('', map { sprintf "%02X", $_ } @hw_addr) . "\@$apname",
                "_raop._tcp",
                 $port,
                "tp=UDP","sm=false","sv=false","ek=1","et=0,1","cn=0,1","ch=2","ss=16","sr=44100",$pw_clause,"vn=3","txtvers=1"; };
            { exec 'dns-sd', '-R',
                join('', map { sprintf "%02X", $_ } @hw_addr) . "\@$apname",
                "_raop._tcp",
                ".",
                 $port,
                "tp=UDP","sm=false","sv=false","ek=1","et=0,1","cn=0,1","ch=2","ss=16","sr=44100",$pw_clause,"vn=3","txtvers=1"; };
            { exec 'mDNSPublish',
                join('', map { sprintf "%02X", $_ } @hw_addr) . "\@$apname",
                "_raop._tcp",
                 $port,
                "tp=UDP","sm=false","sv=false","ek=1","et=0,1","cn=0,1","ch=2","ss=16","sr=44100",$pw_clause,"vn=3","txtvers=1"; };
            die "could not run avahi-publish-service nor dns-sd nor mDNSPublish";
        }

	return $pid
}

sub handleSocketConnect()
{
    my $socket = shift;
    my $player = $players{$socket};

    my $new = $socket->accept;
    $log->info("New connection from".$new->peerhost);
    
    $new->blocking(0);
    $connections{$new} = {socket => $socket, player => $player};

    # Add us to the select loop so we get notified
    Slim::Networking::Select::addRead($new, \&handleSocketRead);
}

sub handleSocketRead()
{
    my $socket = shift;

    if (eof($socket)) {
        $log->debug("Closed: ".$socket);

        Slim::Networking::Select::removeRead($socket);	

        close $socket;
        
        delete $connections{$socket} 
    } else {
        conn_handle_data($socket);
    }
}

sub conn_handle_data {
    my $socket = shift;

    my $conn = $connections{$socket};

    $log->debug("handle data 1");

    if ($conn->{req_need}) {
        if (length($conn->{data}) >= $conn->{req_need}) {
            $conn->{req}->content(substr($conn->{data}, 0, $conn->{req_need}, ''));
            conn_handle_request($socket, $conn);
        }
        undef $conn->{req_need};
        return;
    }

    read $socket, my $data, 4096;
    $conn->{data} .= $data;

    if ($conn->{data} =~ /(\r\n\r\n|\n\n|\r\r)/) {
        my $req_data = substr($conn->{data}, 0, $+[0], '');
        $conn->{req} = HTTP::Request->parse($req_data);
        $log->debug("REQ: ".$conn->{req}->method);
        conn_handle_request($socket, $conn);
        conn_handle_data($socket) if length($conn->{data});
    }
}

sub digest_ok {
    my ($req, $conn) = @_;
    my $authz = $req->header('Authorization');
    return 0 unless $authz =~ s/^Digest\s+//i;
    return 0 unless length $conn->{nonce};
    my @authz = split /,\s*/, $authz;
    my %authz = map { /(.+)="(.+)"/; ($1, $2) } @authz;

    # not a standard digest - uses capital hex digits, in conflict with the RFC
    my $digest = uc md5_hex (
        uc(md5_hex($authz{username} . ':' . $authz{realm} . ':' . $conn->{password}))
        . ':' . $authz{nonce} . ':' .
        uc(md5_hex($req->method . ':' . $authz{uri}))
    );

    return $digest eq $authz{response};
}

sub conn_handle_request {
    my ($socket, $conn) = @_;

    my $req = $conn->{req};
    my $clen = $req->header('content-length') // 0;
    if ($clen > 0 && !length($req->content)) {
        $conn->{req_need} = $clen;
        return; # need more!
    }

    my $resp = HTTP::Response->new(200);
    $resp->request($req);
    $resp->protocol($req->protocol);

    $resp->header('CSeq', $req->header('CSeq'));
    $resp->header('Audio-Jack-Status', 'connected; type=analog');

    if (my $chall = $req->header('Apple-Challenge')) {
        my $data = decode_base64($chall);
        my $ip = $socket->sockhost;
        if ($ip =~ /((\d+\.){3}\d+)$/) { # IPv4
            $data .= join '', map { chr } split(/\./, $1);
        } else {
            $data .= ip6bin($ip);
        }

	my @hw_addr = +(map(ord, split(//, md5($conn->{player}->name()))))[0..5];

        $data .= join '', map { chr } @hw_addr;
        $data .= chr(0) x (0x20-length($data));

        $rsa->use_pkcs1_padding;    # this isn't hashed before signing
        my $signature = encode_base64 $rsa->private_encrypt($data), '';
        $signature =~ s/=*$//;
        $resp->header('Apple-Response', $signature);
    }

    if (length $conn->{password}) {
        if (!digest_ok($req, $conn)) {
            my $nonce = md5_hex(map { rand } 1..20);
            $conn->{nonce} = $nonce;
            my $apname = $conn->{player}->name();
            $resp->header('WWW-Authenticate', "Digest realm=\"$apname\", nonce=\"$nonce\"");
            $resp->code(401);
            $req->method('DENIED');
        }
    }

    for ($req->method) {
        /^OPTIONS$/ && do {
            $resp->header('Public', 'ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER');
            last;
        };

        /^ANNOUNCE$/ && do {
                my $sdp = Net::SDP->new($req->content);
                my $audio = $sdp->media_desc_of_type('audio');

                print $audio->as_string();
                print $audio->attribute('aesiv');

                die("no AESIV") unless my $aesiv = decode_base64($audio->attribute('aesiv'));
                die("no AESKEY") unless my $rsaaeskey = decode_base64($audio->attribute('rsaaeskey'));
                $rsa->use_pkcs1_oaep_padding;
                my $aeskey = $rsa->decrypt($rsaaeskey) || die "RSA decrypt failed";

                $conn->{aesiv} = $aesiv;
                $conn->{aeskey} = $aeskey;
                $conn->{fmtp} = $audio->attribute('fmtp');
                last;
        };

        /^SETUP$/ && do {
            my $transport = $req->header('Transport');
            $transport =~ s/;control_port=(\d+)//;
            my $cport = $1;
            $transport =~ s/;timing_port=(\d+)//;
            my $tport = $1;
            $transport =~ s/;server_port=(\d+)//;
            my $dport = $1;
            $resp->header('Session', 'DEADBEEF');

            my %dec_args = (
                iv      =>  unpack('H*', $conn->{aesiv}),
                key     =>  unpack('H*', $conn->{aeskey}),
                fmtp    => $conn->{fmtp},
                cport   => $cport,
                tport   => $tport,
                dport   => $dport,
            );
            $dec_args{pipe} = $pipepath if defined $pipepath;

            my $dec = '"' . $hairtunes_cli . '"' . join(' ', '', map { sprintf "%s '%s'", $_, $dec_args{$_} } keys(%dec_args));
            $log->debug("decode command: $dec");
            
            my $decoder = open2(my $dec_out, my $dec_in, $dec);

            $conn->{decoder_pid} = $decoder;
            $conn->{decoder_fh} = $dec_in;
            
            my $portdesc = <$dec_out>;
            die("Expected port number from decoder; got $portdesc") unless $portdesc =~ /^port: (\d+)/;
            my $port = $1;

            my $portdesc = <$dec_out>;
            die("Expected cport number from decoder; got $portdesc") unless $portdesc =~ /^cport: (\d+)/;
            my $cport = $1;

            my $portdesc = <$dec_out>;
            die("Expected hport number from decoder; got $portdesc") unless $portdesc =~ /^hport: (\d+)/;
            my $hport = $1;
            
            
            $log->info("launched decoder: $decoder on ports: $port/$cport/$hport");
            $resp->header('Transport', $req->header('Transport') . ";server_port=$port");

            my $host = Slim::Utils::Network::serverAddr();
            my $url = "airplay://$host:$hport/stream.wav";
            $conn->{player}->execute( [ 'playlist', 'play', $url ] );
            
            last;
        };

        /^RECORD$/ && last;
        /^FLUSH$/ && do {
            my $dfh = $conn->{decoder_fh};
            print $dfh "flush\n";
            last;
        };
        /^TEARDOWN$/ && do {
            $resp->header('Connection', 'close');
            close $conn->{decoder_fh};
            last;
        };
        /^SET_PARAMETER$/ && do {
            my @lines = split /[\r\n]+/, $req->content;
                $log->debug("SET_PARAMETER req: " . $req->content);
            my %content = map { /^(\S+): (.+)/; (lc $1, $2) } @lines;
            my $cfh = $conn->{decoder_fh};
            if (exists $content{volume}) {
                my $volume = $content{volume};
                my $percent = 100 + ($volume * 3.35);
                
                $conn->{player}->execute( [ 'mixer', 'volume', $percent ] );
                            
                $log->debug("sending-> vol: ". $percent);
            } else {
                $log->error("unable to perform content for req: " . $req->content);

            }
            last;
        };
        /^GET_PARAMETER$/ && do {
            my @lines = split /[\r\n]+/, $req->content;
                $log->debug("GET_PARAMETER req: " . $req->content);
                
            my %content = map { /^(\S+): (.+)/; (lc $1, $2) } @lines;
            
            last;
        
        };
        /^DENIED$/ && last;
        die("Unknown method: $_");
    }

    $log->debug($resp->as_string("\r\n"));
    
    print $socket $resp->as_string("\r\n");
    $socket->flush;
}


1;

__DATA__
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA59dE8qLieItsH1WgjrcFRKj6eUWqi+bGLOX1HL3U3GhC/j0Qg90u3sG/1CUt
wC5vOYvfDmFI6oSFXi5ELabWJmT2dKHzBJKa3k9ok+8t9ucRqMd6DZHJ2YCCLlDRKSKv6kDqnw4U
wPdpOMXziC/AMj3Z/lUVX1G7WSHCAWKf1zNS1eLvqr+boEjXuBOitnZ/bDzPHrTOZz0Dew0uowxf
/+sG+NCK3eQJVxqcaJ/vEHKIVd2M+5qL71yJQ+87X6oV3eaYvt3zWZYD6z5vYTcrtij2VZ9Zmni/
UAaHqn9JdsBWLUEpVviYnhimNVvYFZeCXg/IdTQ+x4IRdiXNv5hEewIDAQABAoIBAQDl8Axy9XfW
BLmkzkEiqoSwF0PsmVrPzH9KsnwLGH+QZlvjWd8SWYGN7u1507HvhF5N3drJoVU3O14nDY4TFQAa
LlJ9VM35AApXaLyY1ERrN7u9ALKd2LUwYhM7Km539O4yUFYikE2nIPscEsA5ltpxOgUGCY7b7ez5
NtD6nL1ZKauw7aNXmVAvmJTcuPxWmoktF3gDJKK2wxZuNGcJE0uFQEG4Z3BrWP7yoNuSK3dii2jm
lpPHr0O/KnPQtzI3eguhe0TwUem/eYSdyzMyVx/YpwkzwtYL3sR5k0o9rKQLtvLzfAqdBxBurciz
aaA/L0HIgAmOit1GJA2saMxTVPNhAoGBAPfgv1oeZxgxmotiCcMXFEQEWflzhWYTsXrhUIuz5jFu
a39GLS99ZEErhLdrwj8rDDViRVJ5skOp9zFvlYAHs0xh92ji1E7V/ysnKBfsMrPkk5KSKPrnjndM
oPdevWnVkgJ5jxFuNgxkOLMuG9i53B4yMvDTCRiIPMQ++N2iLDaRAoGBAO9v//mU8eVkQaoANf0Z
oMjW8CN4xwWA2cSEIHkd9AfFkftuv8oyLDCG3ZAf0vrhrrtkrfa7ef+AUb69DNggq4mHQAYBp7L+
k5DKzJrKuO0r+R0YbY9pZD1+/g9dVt91d6LQNepUE/yY2PP5CNoFmjedpLHMOPFdVgqDzDFxU8hL
AoGBANDrr7xAJbqBjHVwIzQ4To9pb4BNeqDndk5Qe7fT3+/H1njGaC0/rXE0Qb7q5ySgnsCb3DvA
cJyRM9SJ7OKlGt0FMSdJD5KG0XPIpAVNwgpXXH5MDJg09KHeh0kXo+QA6viFBi21y340NonnEfdf
54PX4ZGS/Xac1UK+pLkBB+zRAoGAf0AY3H3qKS2lMEI4bzEFoHeK3G895pDaK3TFBVmD7fV0Zhov
17fegFPMwOII8MisYm9ZfT2Z0s5Ro3s5rkt+nvLAdfC/PYPKzTLalpGSwomSNYJcB9HNMlmhkGzc
1JnLYT4iyUyx6pcZBmCd8bD0iwY/FzcgNDaUmbX9+XDvRA0CgYEAkE7pIPlE71qvfJQgoA9em0gI
LAuE4Pu13aKiJnfft7hIjbK+5kyb3TysZvoyDnb3HOKvInK7vXbKuU4ISgxB2bB3HcYzQMGsz1qJ
2gG0N5hvJpzwwhbhXqFKA4zaaSrw622wDniAK5MlIE0tIAKKP4yxNGjoD2QYjhBGuhvkWKY=
-----END RSA PRIVATE KEY-----
