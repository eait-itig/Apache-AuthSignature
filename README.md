# Apache::AuthSignature

Apache::AuthSignature provides an authentication module for Apache 
that supports HTTP Signature Authentication.

## Installation

- install mod_perl
- install Net::SSH::Perl
- probably some other stuff

## Configuration

Apache::AuthSignature attempts to be a well behaved Apache HTTPd
module, and therefore tries to support configuration via directives
in the web server configuration file. The main exception to this
is users of the module must provide (ie, write) a perl module that
maps the keyIds in Signature Authorization headers to a username
and SSH public key. In the example below, the Key 

The following demonstrates the basic usage of the module:

```
PerlLoadModule Apache::AuthSignature
PerlLoadModule Custom::KeyHandler

PerlAuthenHandler Apache::AuthSignature
AuthSignatureKeyHandler Custom::KeyHandler
AuthType Signature
AuthName "EAIT Source"
Require valid-user
```

## Key Handler

Apache::AuthSignature calls a `handler` subroutine in the package
specified by the `AuthSignatureKeyHandler` configuration parameter
to fetch a username for the current request, and the public SSH key
to perform signature verification with. The key handler is called
with the current requests Apache2::RequestRec, the type of key
that's being requested, and the keyId parameter from the Authorization
header.

An example key handler package is:

```{perl}
package Custom::KeyHandler;

use Apache2::RequestRec;
use Apache2::Const qw(:common);

my $keys = {
	'ecdsa' => {
		'/user1/keys/[fingerprint]' => {
			'u' => 'username',
			'k' => 'ecdsa-sha2-nistp256 ...',
		},
	},
	'rsa' => {
		'/user1/keys/[fingerprint]' => {
			'u' => 'username',
			'k' => 'ssh-rsa ...',
		},
		'/user2/keys/[fingerprint]' => {
			'u' => 'usernom',
			'k' => 'ssh-rsa ...
		},
	},
	'ed25519' => {
		'/user2/keys/[fingerprint]' => {
			'u' => 'usernom',
			'k' => 'ssh-ed25519 ...',
		},
	},
};

sub handler {
	my ($r, $keyType, $keyId) = @_;

	return Apache2::Const::NOT_FOUND unless
	    defined $keys->{$keyType} and
	    defined $keys->{$keyType}->{$keyId};

	my $stuff = $keys->{$keyType}->{$keyId};
	return (Apache2::Const::OK, $stuff->{'u'}, $stuff->{'k'});
}

1;
```
