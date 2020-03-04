package Apache::AuthSignature;

use strict;
use warnings;

use version; our $VERSION = qv('0.0.0');

use mod_perl2;

use Apache2::Const qw(:common :override :cmd_how :authz_status);
use Apache2::Access;
use Apache2::Connection;
use Apache2::RequestUtil;
use Apache2::Log;
use Apache2::CmdParms;
use Apache2::Directive;
use Apache2::Module;
use APR::Table;
use APR::Date; # for parse_rfc
use APR::Base64;

use Net::SSH::Perl::Key;
use Net::SSH::Perl::Buffer;

use constant {
	InvalidHeaderError	=> 'InvalidHeaderError',
	InvalidParamsError	=> 'InvalidParamsError',
	MissingHeaderError	=> 'MissingHeaderError',
	ExpiredRequestError	=> 'ExpiredRequestError',
};

my @directives = (
	{
		name		=> 'AuthSignatureClockSkew',
		func		=> __PACKAGE__ . '::ClockSkewParam',
		req_override	=> Apache2::Const::OR_AUTHCFG |
		    Apache2::Const::RSRC_CONF,
		args_how	=> Apache2::Const::TAKE1,
		errmsg		=> 'AuthSignatureClockSkew seconds',
	},
	{
		name		=> 'AuthSignatureAuthzHeader',
		func		=> __PACKAGE__ . '::AuthzHeaderParam',
		req_override	=> Apache2::Const::OR_AUTHCFG |
		    Apache2::Const::RSRC_CONF,
		args_how	=> Apache2::Const::TAKE1,
		errmsg		=> 'AuthSignatureAuthzHeader header',
	},
	{
		name		=> 'AuthSignatureWAuthHeader',
		func		=> __PACKAGE__ . '::WAuthHeaderParam',
		req_override	=> Apache2::Const::OR_AUTHCFG |
		    Apache2::Const::RSRC_CONF,
		args_how	=> Apache2::Const::TAKE1,
		errmsg		=> 'AuthSignatureWAuthHeader header',
	},
	{
		name		=> 'AuthSignatureHeaders',
		func		=> __PACKAGE__ . '::HeadersParam',
		req_override	=> Apache2::Const::OR_AUTHCFG |
		    Apache2::Const::RSRC_CONF,
		args_how	=> Apache2::Const::ITERATE,
		errmsg		=> 'AuthSignatureHeaders header ...',
	},
	{
		name		=> 'AuthSignatureKeyHandler',
		func		=> __PACKAGE__ . '::KeyHandlerParam',
		req_override	=> Apache2::Const::OR_AUTHCFG |
		    Apache2::Const::RSRC_CONF,
		args_how	=> Apache2::Const::TAKE1,
		errmsg		=> 'AuthSignatureKeyHandler Pacakge',
	},
);

Apache2::Module::add(__PACKAGE__, \@directives);

sub options_create {
	my ($class, $parms) = @_;
	return bless {
		'clock_skew' => undef,
		'authz_header' => undef,
		'wauth_header' => undef,
		'key_handler' => undef,
		'headers' => [],
	}, $class;
}

sub DIR_CREATE { return options_create(@_); }
sub SERVER_CREATE { return options_create(@_); }

sub options_merge {
	my ($base, $add) = @_;
	my %options;

	my @defs = ('clock_skew', 'authz_header', 'wauth_header', 'key_handler');
	foreach my $def (@defs) {
		$options{$def} = $add->{$def} || $base->{$def};
	}

	$options{'headers'} = scalar @{ $add->{'headers'} } ?
	    $add->{'headers'} : $base->{'headers'};

	return bless \%options, ref($base);
}

sub DIR_MERGE { return options_merge(@_); }
sub SERVER_MERGE { return options_merge(@_); }

sub ClockSkewParam {
	my ($self, $parms, $clock_skew) = @_;

	if ($clock_skew !~ /^\d+$/) {
		die sprintf "%s is not a number", $clock_skew;
	}

	if ($clock_skew < 1) {
		die sprintf "clock skew %d is too low", $clock_skew;
	}

	$self->{'clock_skew'} = $clock_skew;
}

sub AuthzHeaderParam {
	my ($self, $parms, $header) = @_;

	$self->{'authz_header'} = $header;
}

sub HeadersParam {
	my ($self, $parms, $header) = @_;

	push @{ $self->{'headers'} }, $header;
}

sub KeyHandlerParam {
	my ($self, $parms, $class) = @_;

	$self->{'key_handler'} = $class;
}

sub verifyRSA {
	my ($r, $hash, $pubkey, $message, $signature) = @_;

	my $key = Net::SSH::Perl::Key->extract_public($pubkey);
	if (!$key or
	    ref $key ne 'Net::SSH::Perl::Key::RSA' or
	    !defined $key->{rsa_pub}) {
		return Apache2::Const::SERVER_ERROR;
	}

	# XXX this is a pretty gross reach into Net::SSH::Perl internals
	return $key->{rsa_pub}->verify_message($signature, $message, $hash, 'v1.5') ?
	    Apache2::Const::OK : Apache2::Const::DECLINED;
}

sub verifyECDSA {
	my ($r, $hash, $pubkey, $message, $signature) = @_;

	my $key = Net::SSH::Perl::Key->extract_public($pubkey);
	if (!$key or !defined $key->{ecdsa}) {
		return Apache2::Const::SERVER_ERROR;
	}

	# XXX this is a pretty gross reach into Net::SSH::Perl internals
	return $key->{ecdsa}->verify_message($signature, $message, $hash) ?
	    Apache2::Const::OK : Apache2::Const::DECLINED;
}

sub verifyEd25519 {
	my ($r, $hash, $pubkey, $message, $signature) = @_;

	if ($hash ne 'sha512') {
		return Apache2::Const::DECLINED;
	}

	my $key = Net::SSH::Perl::Key->extract_public($pubkey);
	if (!$key or
	    ref $key ne 'Net::SSH::Perl::Key::Ed25519' or
	    !defined $key->{pub}) {
		return Apache2::Const::SERVER_ERROR;
	}

	# build a SSH2 structured sig blob for Net::SSH::Perl::Key:Ed25519
	# to pull apart again.
	my $b = Net::SSH::Perl::Buffer->new( MP => 'SSH2' );
	$b->put_str($key->ssh_name);
	$b->put_str($signature);

	# instead call Net::SSH::Perl::Key:Ed25519::ed25519_verify_message?

	return $key->verify($b->bytes, $message) ?
	    Apache2::Const::OK : Apache2::Const::DECLINED;
}

my %algorithms = (
	'rsa'		=> \&verifyRSA,
	'ecdsa'		=> \&verifyECDSA,
	'ed25519'	=> \&verifyEd25519,
);

sub note_auth_failure($$$$) {
	my ($r, $config, $code, $msg) = @_;

	$r->notes->add('AuthSignatureErrorCode', $code);
	$r->notes->add('AuthSignatureError', $msg);
	$r->err_headers_out->add('AuthSignatureErrorCode' => $code);
	$r->err_headers_out->add('AuthSignatureError' => $msg);

	if (!defined $r->headers_in($config->{'authz_header'})) {
		my @tokens = ( sprintf("realm=\"%s\"", $r->auth_name) );

		if (scalar @{ $config->{'headers'} }) {
			my @headers = map { lc } @{ $config->{'headers'} };
			push @tokens, sprintf("headers=\"%s\"", join(' ', @headers));
		}

		my $header = 'Signature ' . join(',', @tokens);
		$r->err_headers_out->add($config->{'wauth_header'} => $header);
	}

	return Apache2::Const::AUTH_REQUIRED;
}

sub handler {
	my ($r) = @_;

	if ($r->auth_type ne 'Signature') {
		#$r->log_error(sprintf "ap_auth_type %s", $r->auth_type);
		return Apache2::Const::DECLINED;
	}
	if (!defined $r->auth_name) {
		$r->log_error(sprintf "need AuthName: %s", $r->uri);
		return Apache2::Const::SERVER_ERROR;
	}

	my $config = {
		'authz_header'	=> 'authorization',
		'wauth_header'	=> 'WWW-Authenticate',
	};
	$config = config_merge($config, Apache2::Module::get_config(__PACKAGE__,
	    $r->server(), $r->per_dir_config()));

	my $handler = $config->{'key_handler'};
	if (!defined $handler) {
		$r->log_error(sprintf "need AuthSignatureKeyHandler: %s", $r->uri);
		return Apache2::Const::SERVER_ERROR;
	}

	my $headers_in = $r->headers_in;

	my $headers = $config->{'headers'} ||
	    [ $headers_in->{'x-date'} ? 'x-date' : 'date' ];
	my $clock_skew = $config->{'clock_skew'} || 300;

	my $authz = $headers_in->{ $config->{'authz_header'} };
	if (!defined $authz) {
		return note_auth_failure($r, $config, MissingHeaderError,
		    sprintf("no %s header present in the request", $config->{'authz_header'}));
	}
	if ($authz !~ /^\s*(\w+)\s+(.+)$/) {
		return note_auth_failure($r, $config,
		    InvalidHeaderError, 'bad param format');
	}

	my $scheme = $1;
	my $payload = $2;

	if ($scheme ne 'Signature') {
		return note_auth_failure($r, $config,
		    InvalidHeaderError, 'scheme was not "Signature"');
	}

	my %params;
	do {
		if ($payload !~ /^\s*([a-zA-Z]+)=\"([^\"]*)\"(,(.*))?$/) {
			return note_auth_failure($r, $config,
			    InvalidHeaderError, 'bad param format');
		}
		$params{$1} = $2;
		$payload = $4;
	} while ($payload);

	if (!$params{'headers'}) {
		$params{'headers'} = [ defined $headers_in->{'x-date'} ? 'x-date' : 'date' ];
	} else {
		$params{'headers'} = split(/ /, $params{'headers'});
	}

	if (!$params{'keyId'}) {
		return note_auth_failure($r, $config,
		    InvalidHeaderError, 'keyId was not specified');
	}
	if (!$params{'algorithm'}) {
		return note_auth_failure($r, $config,
		    InvalidHeaderError, 'algorithm was not specified');
	}
	if (!$params{'signature'}) {
		return note_auth_failure($r, $config,
		    InvalidHeaderError, 'signature was not specified');
	}

	my ($keyType, $algType) = split(/-/, lc($params{'algorithm'}), 2);
	if (!defined $algType || !defined $algorithms{$keyType}) {
		return note_auth_failure($r, $config, InvalidHeaderError,
		    sprintf("%s is not supported", $params{'algorithm'}));
	}
	my $algorithm = $algorithms{$keyType};

	my %signed;
	my @bits;
	foreach my $key (@{ $params{'headers'} }) {
		$key = lc($key);
		my $value;

		if ($key eq '(request-target)') {
			$value = sprintf("%s %s", lc($r->method), $r->unparsed_uri);
		} elsif ($key eq '(keyid)') {
			$value = $params{'keyId'};
		} elsif ($key eq '(algorithm)') {
			$value = $params{'algorithm'};
		} else {
			$value = $headers_in->{$key};
			if (!defined $value) {
				return note_auth_failure($r, $config,
				    MissingHeaderError,
				    sprintf("%s was not in the request", $key));
			}
		}

		push @bits, "$key: $value";
		$signed{$key} = 1;
	}

	foreach my $key (@{ $headers }) {
		$key = lc($key);
		if (!defined $signed{$key}) {
			return note_auth_failure($r, $config, MissingHeaderError,
			    sprintf("%s was not a signed header", $key));
		}
	}

	if ($signed{'date'} || $signed{'x-date'}) {
		my $date = APR::Date::parse_rfc($headers_in->{'x-date'} ||
		    $headers_in->{'date'});
		my $skew = abs($r->request_time - $date);
		if ($skew > $clock_skew) {
			return note_auth_failure($r, $config, ExpiredRequestError,
			    sprintf("clock skew of %u was greater than %us",
			    $skew, $clock_skew));
		}
	}

	my ($keyStatus, $user, $key) =
	    $handler->handler($r, $keyType, $params{'keyId'});
	if ($keyStatus != Apache2::Const::OK) {
		return Apache2::Const::AUTH_REQUIRED;
	}

	if ($algorithm->($r, $algType, $key, join("\n", @bits),
	    APR::Base64::decode($params{'signature'})) != Apache2::Const::OK) {
		return Apache2::Const::AUTH_REQUIRED;
	}

	$r->auth_type('Signature');
	$r->user($user);
	return Apache2::Const::OK;
}
