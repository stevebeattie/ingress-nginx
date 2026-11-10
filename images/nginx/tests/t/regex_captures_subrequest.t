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

# Regression test for CVE-2026-60005, rootfs/patches/50_*: in a cloned
# subrequest, a regex that does not match must not leave $1 pointing at
# whatever the new captures array holds.
#
# A cloned subrequest, here a cache background update, starts with the main
# request's captures and allocates a new captures array on its first match
# attempt with a regex that has captures.  Before the fix, a failed attempt
# kept the main request's capture count, so $1 then read offsets from the
# new array and applied them to the main request's subject string.
#
# Under AddressSanitizer the new array is filled with one byte value, so the
# offsets would be equal and $1 empty, the same as with the fix.  The map
# regex below is built to fail only after group 1 matched its whole subject:
# with PCRE1, the library build.sh links, (*COMMIT) then leaves the group's
# offsets, 0 and 11, in the array.  Without the fix, $1 is 11 bytes of the
# main request's buffer starting at its URI "/t", that is "/t HTTP/1.0";
# with the fix it is empty.
#
# PCRE2 would hide the bug here: nginx copies offsets out of its match data
# only after a match.  The first subtest checks that the failed match still
# leaves its offsets in the array.  A second background update, with no regex
# in the subrequest, checks that a fix does not drop the captures a cloned
# subrequest inherits.

###############################################################################

use warnings;
use strict;

use Test::More;

use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy cache map rewrite/)->plan(6)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path  %%TESTDIR%%/cache  keys_zone=one:1m;

    # 11 characters, more than the URI "/t"
    map 0123456789a $no_match {
        volatile;
        "~^(.*)(*COMMIT)(*FAIL)"  1;
        default                   "";
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        proxy_cache one;

        # fill the cache without evaluating $no_match or $1
        location = /fill {
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
            proxy_cache_key k;
        }

        location = /fill-inherit {
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
            proxy_cache_key k-inherit;
        }

        # the regex sets the main request's captures
        location ~ ^/(t)$ {
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
            proxy_cache_key k;
            proxy_cache_use_stale updating;
            proxy_cache_background_update on;
            proxy_set_header X-Capture $no_match$1;
        }

        # the background update uses the inherited $1, "i"
        location ~ ^/(i)nherit$ {
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
            proxy_cache_key k-inherit;
            proxy_cache_use_stale updating;
            proxy_cache_background_update on;
            proxy_set_header X-Capture $1;
        }

        # no subrequest: $no_match overwrites the offsets of $1 with its own
        location ~ ^/(p)robe$ {
            return 200 "probe=[$no_match$1]\n";
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location / {
            add_header Cache-Control max-age=1;
            return 200 "capture=[$http_x_capture] id=$request_id\n";
        }
    }
}

EOF

$t->run();

###############################################################################

like(http_get('/probe'), qr/probe=\[\/probe HTTP\]/,
	'failed match leaves its offsets');

my ($id) = http_get('/fill') =~ /capture=\[\] id=(\w+)/;
my ($inherit_id) = http_get('/fill-inherit') =~ /capture=\[\] id=(\w+)/;
ok($id && $inherit_id, 'cache filled');

# the cached responses expire after 1 second
sleep 2;

my $r = update('/t', $id);
like($r, qr/id=(?!\Q$id\E)/, 'background update cached');
like($r, qr/capture=\[\] /, 'no stale capture in background update');

$r = update('/inherit', $inherit_id);
like($r, qr/id=(?!\Q$inherit_id\E)/, 'inherited capture: update cached');
like($r, qr/capture=\[i\] /, 'inherited capture passed to background update');

###############################################################################

# Requests $uri, which serves the stale cached response with id $id and
# starts a background update, then waits until the cache holds the update's
# response, and returns it.

sub update {
	my ($uri, $id) = @_;

	my $r = http_get($uri);
	return $r unless $r =~ /id=\Q$id\E/;

	for (1 .. 100) {
		$r = http_get($uri);
		last if $r =~ /id=(?!\Q$id\E)/;
		select undef, undef, undef, 0.1;
	}

	return $r;
}

###############################################################################
