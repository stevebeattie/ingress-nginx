#!/usr/bin/perl

# Copyright 2026 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Regression test for CVE-2026-1642, rootfs/patches/49_*: nginx must not
# accept a plain text response from an SSL upstream before the SSL handshake
# has started.
#
# nginx starts the handshake from the upstream connection's write handler.
# The bug needs the response to arrive before that handler first runs: epoll
# then reports the connection readable and writable at once, and nginx runs
# the read handler first.  A backend on loopback rarely answers that fast, so
# the request also has a mirror subrequest.  nginx runs it right after the
# upstream connect() returns, before it polls again, and the subrequest's URI
# makes a regex location backtrack for some tens of milliseconds; three of
# them give the backend below time to accept the connection and write its
# response.

###############################################################################

use warnings;
use strict;

use IO::Select;
use IO::Socket::INET;
use Test::More;

use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

# Every "a" doubles the time the regex in /delay/ takes to fail.  With 22,
# PCRE reaches its match limit, which nginx logs as an alert; to wait longer,
# add mirrors instead.
my $delay_uri = '/delay/' . ('a' x 20) . '!';

my $t = Test::Nginx->new()->has(qw/http proxy http_ssl mirror rewrite/)
	->has_daemon('openssl')->plan(4)
	->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            mirror $delay_uri;
            mirror $delay_uri;
            mirror $delay_uri;
            proxy_pass https://127.0.0.1:%%PORT_8081%%;
        }

        location /delay/ {
            return 204;
        }

        location ~ ^/delay/(a+)+\$ {
            return 204;
        }

        # an SSL upstream that completes the handshake
        location /ssl {
            proxy_pass https://127.0.0.1:%%PORT_8082%%;
        }
    }

    server {
        listen       127.0.0.1:8082 ssl;
        server_name  localhost;

        ssl_certificate_key  localhost.key;
        ssl_certificate      localhost.crt;

        location / {
            return 200 "SSL OK\\n";
        }
    }
}

EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

system('openssl req -x509 -new '
	. "-config $d/openssl.conf -subj /CN=localhost/ "
	. "-out $d/localhost.crt -keyout $d/localhost.key "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't create certificate for localhost: $!\n";

$t->run_daemon(\&plain_text_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

like(http_get('/ssl'), qr/SSL OK/, 'SSL upstream response passed');

# If the response arrives only after the handshake has started, nginx fails
# the handshake instead, and the attempt proves nothing.  Try again then.
my ($r, $injected);
for (1 .. 5) {
	$r = http_get('/');
	$injected //= $r if $r =~ /INJECTED/;
	last if $t->read_file('error.log') =~ /upstream prematurely sent response/;
}

is($injected, undef, 'plain text response not passed to the client');
like($r, qr/^HTTP\/1\.1 502 /, 'bad gateway');
like($t->read_file('error.log'), qr/upstream prematurely sent response/,
	'premature response detected');

###############################################################################

# A backend that answers in plain text as soon as it accepts a connection,
# without waiting for a request or a TLS ClientHello.

sub plain_text_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => '127.0.0.1:' . port(8081),
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		print $client "HTTP/1.1 200 OK\r\n"
			. "Content-Length: 9\r\n"
			. "Connection: close\r\n"
			. "\r\n"
			. "INJECTED\n";

		IO::Select->new($client)->can_read(5);
		close $client;
	}
}

###############################################################################
