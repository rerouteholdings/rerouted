#!/bin/sh
# install-ubuntu.sh: installs a rerouted homeserver from binaries, on Ubuntu 22.04 or later
# (Debian 12 too). It creates the users, installs the binaries, writes the settings,
# installs the locked-down systemd units and the AppArmor profiles, and starts it.
#
#   sudo deploy/install-ubuntu.sh BINARIES NAME [HANDLES]
#
# Run it from this directory, deploy/: the units and profiles it installs are the files
# next to it. To install on another machine, copy deploy/ and the binaries there.
#
# BINARIES is a directory with the rerouted binary, or the binary itself. With the other
# three next to it, rerouted is split into the processes docs/security-architecture.md
# describes, each with its own user and sandbox:
#
#   rerouted-keyd    holds the server keys, encrypted on disk (needs systemd 250)
#   rerouted-sfu     runs voice channels' UDP and WebRTC
#   rerouted-egress  makes the connections out, so rerouted has no network (needs systemd
#                    250, and rerouted-sfu)
#
# Each is installed if its binary is there and this systemd can run it: Ubuntu 24.04 runs
# all of them, 22.04 (systemd 249) only rerouted-sfu. Binaries may have a release's names,
# such as rerouted-keyd-linux-amd64. To build them:
#
#   for c in rerouted rerouted-keyd rerouted-sfu rerouted-egress; do
#     CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/$c ./cmd/$c
#   done
#
# NAME is the server's DNS name, such as chat.example. It's the server's identity, in every
# user's chain: choose it once. HANDLES is the domain usernames are given out under, such as
# @kat.chat.example for chat.example; it defaults to NAME.
#
# Run it again with new binaries to upgrade: the settings, the registration code among
# them, the keys, and the data are kept. A process installed before stays, whether or not
# its binary is given again: the script never takes one away. APPARMOR=0 skips the AppArmor
# profiles.
#
# rerouted listens on 127.0.0.1:8080, for a reverse proxy. The script leaves configurations
# for your names in /etc/rerouted, for nginx (nginx.conf.example, and
# nginx-handles.conf.example for usernames, which needs a wildcard certificate) and for
# Caddy (Caddyfile.example, which needs none). The nginx ones use the certificate for NAME
# where acme.sh --install-cert put it in /etc/ssl (certs/NAME-fullchain.cer,
# private/NAME.key) or where certbot keeps it, whichever is there; CERT=FULLCHAIN
# KEY=KEYFILE names another.
#
# With nginx installed, and a certificate found, it turns the nginx ones on as well: as
# /etc/nginx/sites-available/rerouted, and rerouted-handles if the certificate covers
# *.HANDLES, linked into sites-enabled, and nginx reloaded, if nginx -t accepts them. A site
# there that has been edited, or turned off, is left alone. NGINX=0 skips this. It doesn't
# get certificates.
set -eu

die() { echo "install-ubuntu.sh: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run it as root: sudo $0 $*"
[ $# -ge 2 ] && [ $# -le 3 ] || die "usage: $0 BINARIES NAME [HANDLES]"
src=$1 name=$2 handles=${3:-$2}
here=$(cd "$(dirname "$0")" && pwd)
units=/etc/systemd/system

# The names: lowercase DNS names, as rerouted needs them.
for n in "$name" "$handles"; do
	printf '%s\n' "$n" | grep -Eq '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$' ||
		die "\"$n\" isn't a DNS name like chat.example (lowercase, no *., no https://)"
done

case "$(uname -m)" in
x86_64) want=62 arch=amd64 ;;
aarch64) want=183 arch=arm64 ;;
*) die "unsupported machine: $(uname -m)" ;;
esac

# The binaries: rerouted, and the others by the same naming next to it.
if [ -d "$src" ]; then
	dir=$src suffix=
	[ -f "$dir/rerouted" ] || suffix=-linux-$arch
	[ -f "$dir/rerouted$suffix" ] || die "$dir has no rerouted or rerouted-linux-$arch in it"
else
	[ -f "$src" ] || die "$src: no such file"
	dir=$(dirname "$src")
	case "$(basename "$src")" in
	rerouted | rerouted-linux-*) suffix=$(basename "$src") suffix=${suffix#rerouted} ;;
	# Under another name, it's rerouted alone.
	*) suffix=//none ;;
	esac
fi
binary() { # binary NAME: where that binary is given, if it is
	if [ "$1" = rerouted ] && [ ! -d "$src" ]; then
		echo "$src"
	elif [ -f "$dir/$1$suffix" ]; then
		echo "$dir/$1$suffix"
	fi
}
# A Linux executable for this machine.
elf() {
	[ "$(od -An -c -N4 "$1" | tr -d ' ')" = '177ELF' ] && [ "$(od -An -tu2 -j18 -N2 "$1" | tr -d ' ')" = "$want" ] ||
		die "$1 isn't a Linux $arch binary: build it with CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -o $2 ./cmd/$2"
}
for c in rerouted rerouted-keyd rerouted-sfu rerouted-egress; do
	b=$(binary $c)
	[ -z "$b" ] || elf "$b" $c
done

command -v systemctl >/dev/null || die "this needs systemd"
sd=$(systemctl --version | awk 'NR==1{print $2}')
[ "$sd" -ge 248 ] || die "systemd $sd is too old for the unit's sandbox: it needs 248 (Ubuntu 22.04 has 249)"

# Which of the other processes: those given that this systemd can run, and those here
# already. Taking rerouted-keyd away would leave rerouted without its keys, so it's never
# done here (docs/run-a-homeserver.md says how).
dropin=$units/rerouted.service.d
keyd= sfu= egress= skipped=
skip() { skipped="$skipped
    $1"; }
if [ -e $dropin/20-sfu.conf ] || [ -n "$(binary rerouted-sfu)" ]; then
	sfu=1
fi
if [ -e $dropin/10-keyd.conf ]; then
	keyd=1
elif [ -n "$(binary rerouted-keyd)" ]; then
	if [ "$sd" -ge 250 ] && command -v systemd-creds >/dev/null; then
		keyd=1
	else
		skip "rerouted-keyd: it needs systemd 250 and systemd-creds, and this is systemd $sd"
	fi
fi
if [ -e $dropin/30-egress.conf ]; then
	egress=1
elif [ -n "$(binary rerouted-egress)" ]; then
	if [ "$sd" -lt 250 ]; then
		skip "rerouted-egress: it needs systemd 250, and this is systemd $sd"
	elif [ -z "$sfu" ]; then
		skip "rerouted-egress: it needs rerouted-sfu's binary too, for voice channels"
	else
		egress=1
	fi
fi

# What's installed comes from this directory.
files="rerouted.service apparmor/rerouted"
[ -z "$keyd" ] || files="$files rerouted-keyd.socket rerouted-keyd.service rerouted-keyd-seal.service rerouted-keyd-seal rerouted.service.d/10-keyd.conf apparmor/rerouted-keyd"
[ -z "$sfu" ] || files="$files rerouted-sfu.socket rerouted-sfu.service rerouted.service.d/20-sfu.conf apparmor/rerouted-sfu"
[ -z "$egress" ] || files="$files rerouted.socket rerouted-egress.socket rerouted-egress.service rerouted.service.d/30-egress.conf apparmor/rerouted-egress"
for f in $files; do
	[ -f "$here/$f" ] || die "$here/$f is missing: run this from rerouted's deploy/ directory, or a whole copy of it"
done

conf=/etc/rerouted
env=$conf/rerouted.env
if [ -e "$env" ]; then
	# Set up before: the name is the server's identity, and mustn't change under its users.
	old=$(sed -n 's/^REROUTED_NAME=//p' "$env" | tail -1)
	[ "$old" = "$name" ] || die "$env already names this server $old, not $name: edit it yourself if you mean to change it"
	# Usernames are under the domain it has, too: the one given must be it.
	oldh=$(sed -n 's/^REROUTED_HANDLES=//p' "$env" | tail -1)
	oldh=${oldh:-$name}
	[ $# -eq 3 ] || handles=$oldh
	[ "$oldh" = "$handles" ] || die "$env already gives usernames under $oldh, not $handles: edit it yourself if you mean to change it"
fi

echo "==> users"
user() { # user NAME: a system user with a group of its own, no password, and no shell
	getent passwd "$1" >/dev/null ||
		useradd --system --user-group --home-dir "/var/lib/$1" --no-create-home --shell /usr/sbin/nologin "$1"
	echo "    $1"
}
user rerouted
[ -z "$keyd" ] || user rerouted-keyd
[ -z "$sfu" ] || user rerouted-sfu
[ -z "$egress" ] || user rerouted-egress

echo "==> binaries"
for c in rerouted ${keyd:+rerouted-keyd} ${sfu:+rerouted-sfu} ${egress:+rerouted-egress}; do
	b=$(binary $c)
	if [ -n "$b" ]; then
		# Into place in one step: the one that's running keeps its file until it restarts.
		install -m 755 -o root -g root "$b" /usr/local/bin/$c.new
		mv /usr/local/bin/$c.new /usr/local/bin/$c
		echo "    /usr/local/bin/$c"
	elif [ -x /usr/local/bin/$c ]; then
		echo "    /usr/local/bin/$c, kept as it is: no new one was given"
	else
		die "$c is set up here, but /usr/local/bin/$c is gone, and no binary for it was given"
	fi
done
[ -z "$keyd" ] || install -D -m 755 -o root -g root "$here/rerouted-keyd-seal" /usr/local/libexec/rerouted-keyd-seal

echo "==> $env"
install -d -m 750 -o root -g rerouted "$conf"
if [ -e "$env" ]; then
	echo "    kept as it is"
else
	code=$(od -An -tx1 -N12 /dev/urandom | tr -d ' \n')
	(
		umask 027
		cat >"$env.new" <<ENV
# rerouted's settings. docs/settings.md describes every one; restart rerouted after a change.

# This server's DNS name: its identity. Don't change it once people have signed up.
REROUTED_NAME=$name

# Usernames are handles under this domain: @kat.$handles.
REROUTED_HANDLES=$handles

REROUTED_DATA_DIR=/var/lib/rerouted
REROUTED_LISTEN=127.0.0.1:8080

# People need this code to sign up. REROUTED_REGISTRATION=closed stops sign-ups.
REROUTED_REGISTRATION=invite
REROUTED_REGISTRATION_CODE=$code
ENV
	)
	chown root:rerouted "$env.new"
	chmod 640 "$env.new"
	mv "$env.new" "$env"
fi

# Where rerouted listens: the reverse proxy's upstream, and, without a network of its own,
# the socket systemd makes for it.
listen=$(sed -n 's/^REROUTED_LISTEN=//p' "$env" | tail -1)
listen=${listen:-127.0.0.1:8080}
case $listen in
:*) upstream=127.0.0.1$listen stream=${listen#:} ;;
*) upstream=$listen stream=$listen ;;
esac

echo "==> units"
unit() { # unit FILE...: into /etc/systemd/system, under the same names
	for f; do
		install -D -m 644 -o root -g root "$here/$f" "$units/$f"
		echo "    $units/$f"
	done
}
unit rerouted.service
[ -z "$keyd" ] || unit rerouted-keyd.socket rerouted-keyd.service rerouted-keyd-seal.service rerouted.service.d/10-keyd.conf
[ -z "$sfu" ] || unit rerouted-sfu.socket rerouted-sfu.service rerouted.service.d/20-sfu.conf
if [ -n "$egress" ]; then
	unit rerouted.socket rerouted-egress.socket rerouted-egress.service rerouted.service.d/30-egress.conf
	sed -i "s|^ListenStream=.*|ListenStream=$stream|" $units/rerouted.socket
fi

if [ "${APPARMOR:-1}" != 0 ] && command -v apparmor_parser >/dev/null && [ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = Y ]; then
	echo "==> AppArmor profiles"
	for c in rerouted ${keyd:+rerouted-keyd} ${sfu:+rerouted-sfu} ${egress:+rerouted-egress}; do
		install -m 644 -o root -g root "$here/apparmor/$c" /etc/apparmor.d/$c
		if apparmor_parser -r -W /etc/apparmor.d/$c; then
			echo "    /etc/apparmor.d/$c"
		else
			rm -f /etc/apparmor.d/$c
			echo "    this AppArmor couldn't load $c's profile: going on without it (the unit's sandbox still applies)" >&2
		fi
	done
else
	echo "==> no AppArmor profiles (APPARMOR=0, or AppArmor isn't on)"
fi

# The certificate nginx is to use: CERT and KEY's, or one found where acme.sh --install-cert
# or certbot leaves NAME's.
findcert() { # findcert NAME: sets cert and key to its certificate's files, or to nothing
	cert= key=
	if [ -f "/etc/ssl/certs/$1-fullchain.cer" ] && [ -f "/etc/ssl/private/$1.key" ]; then
		cert=/etc/ssl/certs/$1-fullchain.cer key=/etc/ssl/private/$1.key
	elif [ -f "/etc/letsencrypt/live/$1/fullchain.pem" ]; then
		cert=/etc/letsencrypt/live/$1/fullchain.pem key=/etc/letsencrypt/live/$1/privkey.pem
	fi
}
covers() { # covers CERT NAME: the certificate is for NAME, itself or by a wildcard
	openssl x509 -in "$1" -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' | sed -n 's/^ *DNS://p' |
		grep -Fxq -e "$2" -e "*.${2#*.}"
}
if [ -n "${CERT:-}${KEY:-}" ]; then
	for f in "${CERT:-}" "${KEY:-}"; do
		case $f in '' | *[!A-Za-z0-9._/+-]* | [!/]*) die "CERT and KEY are both needed, as full paths: \"$f\" isn't one" ;; esac
		[ -f "$f" ] || die "$f: no such file"
	done
	cert=$CERT key=$KEY
else
	findcert "$name"
fi
# certfor: yes, the certificate found is for NAME; no, it isn't; none, there isn't one,
# and the configuration has certbot's paths, to fill later.
if [ -z "$cert" ]; then
	certfor=none
	cert=/etc/letsencrypt/live/$name/fullchain.pem key=/etc/letsencrypt/live/$name/privkey.pem
elif covers "$cert" "$name"; then
	certfor=yes
else
	certfor=no
fi
# Usernames: the same certificate if it covers *.HANDLES, or one of HANDLES's own that does.
# Otherwise the same files, for when they do: a certificate issued again, with the wildcard
# added, lands where it was.
hcert=$cert hkey=$key wild=
if [ $certfor != none ] && covers "$cert" "*.$handles"; then
	wild=1
else
	mcert=$cert mkey=$key
	findcert "$handles"
	if [ -n "$cert" ] && covers "$cert" "*.$handles"; then
		hcert=$cert hkey=$key wild=1
	elif [ $certfor = none ]; then
		hcert=/etc/letsencrypt/live/$handles/fullchain.pem hkey=/etc/letsencrypt/live/$handles/privkey.pem
	fi
	cert=$mcert key=$mkey
fi

# For nginx: the server's own name, and, apart, the usernames under it, which need a
# certificate for *.HANDLES. Three things nginx doesn't do unasked, and rerouted needs: the
# request's own Host (rerouted tells its names and its handles apart by it), bodies over
# 1 MB (files are up to 64 MiB), and the WebSocket upgrade for the client stream.
sed -e "s/@NAME@/$name/g" -e "s/@HANDLES@/$handles/g" -e "s/@UPSTREAM@/$upstream/g" \
	-e "s|@CERT@|$cert|g" -e "s|@KEY@|$key|g" >$conf/nginx.conf.example <<'NGINX'
# rerouted behind nginx, for @NAME@. Install as /etc/nginx/sites-available/rerouted, link
# it into sites-enabled, then: nginx -t && systemctl reload nginx
#
# The certificate is the one install-ubuntu.sh found for @NAME@, or certbot's paths if it
# found none: change them if yours is elsewhere.

# The WebSocket upgrade, for the client stream.
map $http_upgrade $rerouted_connection {
	default upgrade;
	""      close;
}

server {
	listen 80;
	listen [::]:80;
	server_name @NAME@;
	return 301 https://$host$request_uri;
}

server {
	listen 443 ssl http2;
	listen [::]:443 ssl http2;
	server_name @NAME@;

	ssl_certificate     @CERT@;
	ssl_certificate_key @KEY@;
	add_header Strict-Transport-Security "max-age=31536000" always;

	# A check for Caddy's certificates on demand: not for the internet.
	location = /v0/tls-ask {
		return 404;
	}

	location ~ ^/(\.well-known/tieroute|v0)/ {
		proxy_pass http://@UPSTREAM@;
		proxy_http_version 1.1;
		# rerouted tells its names apart by Host, and counts rate limits by this address.
		proxy_set_header Host $host;
		proxy_set_header X-Forwarded-For $remote_addr;
		proxy_set_header Upgrade $http_upgrade;
		proxy_set_header Connection $rerouted_connection;
		# Files are up to 64 MiB. Streams stay open, quiet for up to 90 seconds, and
		# what they send goes out as it comes.
		client_max_body_size 65m;
		proxy_read_timeout 180s;
		proxy_send_timeout 180s;
		proxy_buffering off;
	}

	location / {
		return 404;
	}
}
NGINX
sed -e "s/@NAME@/$name/g" -e "s/@HANDLES@/$handles/g" -e "s/@UPSTREAM@/$upstream/g" \
	-e "s|@CERT@|$hcert|g" -e "s|@KEY@|$hkey|g" >$conf/nginx-handles.conf.example <<'NGINX'
# Usernames under @HANDLES@ (@kat.@HANDLES@), behind nginx: each one's handle document,
# which is how other servers find it. Install as /etc/nginx/sites-available/rerouted-handles
# once you have a certificate that covers *.@HANDLES@, link it into sites-enabled, then:
# nginx -t && systemctl reload nginx
#
# A wildcard certificate needs Let's Encrypt's DNS challenge, through your DNS provider's
# API. With acme.sh, one certificate for both names, then --install-cert as before:
#   acme.sh --issue --dns dns_PROVIDER -d @NAME@ -d '*.@HANDLES@'
# With certbot, its plugin for your provider, or by hand:
#   certbot certonly --manual --preferred-challenges dns -d '*.@HANDLES@'

server {
	listen 80;
	listen [::]:80;
	server_name *.@HANDLES@;
	return 301 https://$host$request_uri;
}

server {
	listen 443 ssl http2;
	listen [::]:443 ssl http2;
	server_name *.@HANDLES@;

	ssl_certificate     @CERT@;
	ssl_certificate_key @KEY@;
	add_header Strict-Transport-Security "max-age=31536000" always;

	location = /.well-known/tieroute/handle {
		proxy_pass http://@UPSTREAM@;
		# The handle is the Host: rerouted answers for the one asked for.
		proxy_set_header Host $host;
		proxy_set_header X-Forwarded-For $remote_addr;
	}

	location / {
		return 404;
	}
}
NGINX
chmod 644 $conf/nginx.conf.example $conf/nginx-handles.conf.example

# For Caddy: it gets a certificate for each handle as it's first looked up, so handles need
# wildcard DNS, but no wildcard certificate.
cat >$conf/Caddyfile.example <<CADDY
{
	on_demand_tls {
		ask http://$upstream/v0/tls-ask
	}
}

$name {
	header Strict-Transport-Security "max-age=31536000"
	@tieroute {
		path /.well-known/tieroute/* /v0/*
		not path /v0/tls-ask
	}
	handle @tieroute {
		reverse_proxy $upstream
	}
	handle {
		respond 404
	}
}

*.$handles {
	tls {
		on_demand
	}
	header Strict-Transport-Security "max-age=31536000"
	handle /.well-known/tieroute/handle {
		reverse_proxy $upstream
	}
	handle {
		respond 404
	}
}
CADDY
chmod 644 $conf/Caddyfile.example

echo "==> starting rerouted"
systemctl daemon-reload
sockets="${keyd:+rerouted-keyd.socket} ${sfu:+rerouted-sfu.socket} ${egress:+rerouted-egress.socket rerouted.socket}"
# The first time systemd is to listen for rerouted, rerouted has to let go of the address.
if [ -n "$egress" ] && ! systemctl is-active --quiet rerouted.socket; then
	systemctl stop rerouted.service 2>/dev/null || true
fi
# shellcheck disable=SC2086
[ -z "$(echo $sockets)" ] || systemctl enable --now $sockets >/dev/null 2>&1 ||
	die "the sockets didn't start: systemctl status $sockets"
systemctl enable rerouted >/dev/null 2>&1
# The other processes restart with it, into their new binaries. Runs of this script close
# together aren't a service failing over and over: systemd's count of starts begins again.
systemctl reset-failed rerouted.service 2>/dev/null || true
systemctl restart rerouted
ok=
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
	sleep 1
	systemctl is-active --quiet rerouted || continue
	# Up, and answering: with curl, ask it; without, running is as much as can be seen.
	if ! command -v curl >/dev/null || curl -fsS --max-time 5 -o /dev/null "http://$upstream/.well-known/tieroute/server" 2>/dev/null; then
		ok=1
		break
	fi
done
if [ -z "$ok" ]; then
	journalctl -u rerouted ${keyd:+-u rerouted-keyd -u rerouted-keyd-seal} -n 30 --no-pager >&2 || true
	die "rerouted didn't start: its log is above"
fi

# nginx: each site there's a certificate for, into sites-available and sites-enabled.
main= users=
nsite() { # nsite SITE EXAMPLE SERVERNAME: sets st to on, or to why it isn't
	avail=/etc/nginx/sites-available/$1 link=/etc/nginx/sites-enabled/$1
	if [ -e "$avail" ] && [ -e "$link" ] && ! cmp -s "$2" "$avail"; then
		st=edited
		echo "    $avail: left as it is, edited since it was $2"
		return 0
	fi
	if [ -e "$avail" ] && [ ! -e "$link" ]; then
		st=off
		echo "    $avail: left turned off (it isn't in sites-enabled)"
		return 0
	fi
	had=
	[ ! -e "$avail" ] || had=1
	install -m 644 -o root -g root "$2" "$avail"
	ln -sf "$avail" "$link"
	# Accepted, and not by ignoring it for another site with the same name.
	if out=$(nginx -t 2>&1) && ! printf '%s\n' "$out" | grep -Fq "conflicting server name \"$3\""; then
		st=on
		echo "    $link"
	else
		[ -n "$had" ] || rm -f "$avail" "$link"
		st=refused
		printf '%s\n' "$out" | sed 's/^/    /' >&2
		echo "    nginx doesn't take $2 as it is: left out" >&2
	fi
}
if [ "${NGINX:-1}" != 0 ] && command -v nginx >/dev/null && [ -d /etc/nginx/sites-available ] && [ -d /etc/nginx/sites-enabled ]; then
	echo "==> nginx"
	if [ $certfor = yes ]; then
		nsite rerouted $conf/nginx.conf.example "$name"
		main=$st
		# An edited site that's on is the operator's own way of serving the name.
		if [ -n "$wild" ] && { [ "$main" = on ] || [ "$main" = edited ]; }; then
			nsite rerouted-handles $conf/nginx-handles.conf.example "*.$handles"
			users=$st
		fi
		if [ "$main" = on ] || [ "$users" = on ]; then
			if systemctl is-active --quiet nginx; then
				systemctl reload nginx || die "nginx didn't reload: journalctl -u nginx"
			else
				echo "    nginx isn't running: the sites are there for when it starts"
			fi
		fi
	else
		echo "    no certificate for $name yet: nothing turned on"
	fi
fi

code=$(sed -n 's/^REROUTED_REGISTRATION_CODE=//p' "$env" | tail -1)
cat <<DONE

rerouted is running as $name, on $upstream.

  Registration code:  ${code:-(none: see $env)}
  Usernames:          @someone.$handles
  Settings:           $env
  Log:                journalctl -u rerouted
DONE
if [ -n "$keyd" ]; then
	cat <<DONE
  Data, to back up:   /var/lib/rerouted, and the server keys, which are apart and
                      encrypted for this machine only: docs/administer-a-homeserver.md,
                      "Back up", has the command that saves them
DONE
else
	echo "  Data, to back up:   /var/lib/rerouted"
fi
echo
echo "  Processes:"
echo "    rerouted         the homeserver${egress:+, with no network of its own}"
[ -z "$keyd" ] || echo "    rerouted-keyd    holds the server keys and signs for it"
[ -z "$sfu" ] || echo "    rerouted-sfu     voice channels; starts when one is first used"
[ -z "$egress" ] || echo "    rerouted-egress  connections out; starts with the first one"
[ -z "$skipped" ] || echo "  Not installed:$skipped"
if [ -n "$egress" ]; then
	echo
	echo "  To stop it: systemctl stop rerouted.socket rerouted. systemd listens for rerouted"
	echo "  now, and starts it again at the next request if only rerouted is stopped."
fi
left="Nobody can reach it yet. Still to do:"
case $main in on | edited) left="What it needs to be reached:" ;; esac
cat <<DONE

$left

  1. DNS: point $name and *.$handles at this server (A, and AAAA if it has IPv6).
DONE
tls="2. TLS"
if command -v nginx >/dev/null || ! command -v caddy >/dev/null; then
	tls="Or TLS"
	if [ "$main" = on ]; then
		echo "  2. TLS: done. nginx serves $name (/etc/nginx/sites-enabled/rerouted), with"
		echo "     the certificate at $cert."
	elif [ "$main" = edited ]; then
		echo "  2. TLS: nginx has /etc/nginx/sites-available/rerouted as you edited it, left alone."
		echo "     What this script would put there now is $conf/nginx.conf.example."
	elif [ "$main" = refused ]; then
		echo "  2. TLS, with nginx: nginx didn't take $conf/nginx.conf.example as a site:"
		echo "     what it said is above. Once that's mended, run this again."
	else
		case $certfor in
		yes) echo "  2. TLS, with nginx: use $conf/nginx.conf.example as a site (its first lines"
			echo "     say how). It uses the certificate at $cert." ;;
		no) echo "  2. TLS, with nginx: the certificate at $cert"
			echo "     isn't for $name. Get one that is, then run this again." ;;
		none) echo "  2. TLS, with nginx: get a certificate for $name, then run this again: it"
			echo "     turns on $conf/nginx.conf.example as a site. CERT= and KEY= say where the"
			echo "     certificate is, if it isn't where acme.sh --install-cert or certbot puts it." ;;
		esac
	fi
	echo "     The server works from then on: people can sign up and talk to each other."
	if [ "$users" = on ]; then
		echo "  3. Usernames: done. nginx serves *.$handles too (rerouted-handles)."
	elif [ "$users" = edited ]; then
		echo "  3. Usernames: nginx has /etc/nginx/sites-available/rerouted-handles as you edited"
		echo "     it, left alone."
	elif [ -n "$wild" ]; then
		echo "  3. Usernames, with nginx: add $conf/nginx-handles.conf.example the same way."
		echo "     The certificate at $hcert covers *.$handles."
	else
		[ $certfor = none ] || echo "  3. Usernames, with nginx: the certificate at $hcert doesn't cover *.$handles."
		[ $certfor != none ] || echo "  3. Usernames, with nginx: they need a certificate for *.$handles."
		cat <<DONE
     Once you have one, run this again: it turns on $conf/nginx-handles.conf.example
     (its first lines say how to get one). Until then, other servers can't look up
     @someone.$handles.
DONE
	fi
fi
if command -v caddy >/dev/null || ! command -v nginx >/dev/null; then
	cat <<DONE
  $tls, with Caddy: use $conf/Caddyfile.example as /etc/caddy/Caddyfile, with
     ports 80 and 443 open. It gets a certificate for each username the first time it's
     looked up: you need the wildcard DNS record, but no wildcard certificate.
DONE
fi
cat <<DONE
  Then check from another machine: curl https://$name/.well-known/tieroute/server
DONE
