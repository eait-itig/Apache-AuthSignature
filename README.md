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
and SSH public key.

The following demonstrates the basic usage of the module:

```
PerlLoadModule Apache::AuthSignature
PerlLoadModule Custom::KeyHandler

PerlAuthenHandler Apache::AuthSignature
AuthSignatureKeyHandler Custom::KeyHandler
AuthType Signature
AuthName "HTTP Signature Auth protected area"
Require valid-user
```

### AuthSignatureKeyHandler

Specifies the name of the package that handles mapping key types
and key identifiers to a username and an SSH public key. See "Key
Handler" below for detail.

### AuthSignatureClockSkew

### AuthSignatureAuthzHeader

Specifies an alternate name for the `Authorization` header. By
default the module uses `Authorization`.

### AuthSignatureWAuthHeader

Specifies an alternate name for the `WWW-Authenticate` header the
server sends to an unauthenticated client. By defualt it uses
`WWW-Authenticate`.

eg:

```
AuthSignatureWAauthHeader X-WWW-Authenticate
```

### AuthSignatureOpaque

Specifies an opaque value for use in `WWW-Authenticate` headers,
and to expect from the client in `Authorization` headers. By default
there is no opaque value used.

### AuthSignatureOpaqueHandler

Specifies a handler package that will provide a custom opaque value
for the request.

### AuthSignatureHeaders

Specifies a list of headers and pseudo-headers that must be signed
by the client to successfully authenticate. The list is also provided
to unauthenticated clients in the `WWW-Authenticate` header. By
default only the `Date` header is required to be signed by clients.

eg:

```
AuthSignatureHeaders date host (request-target) (keyid)
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

```perl
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
			'k' => 'ssh-rsa ...',
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

# Integration with other authentication schemes.

Apache HTTPd only supports having a single authentication provider
configured at a time, which means it is difficult to support both
Signature and another type such as Basic or Digest concurrently.
Custom authentication types that combine the AuthSignature functionality
with other authentication types can be written in Perl. To support
that, the module provides a `AuthSignatureHandler` subroutine that
can be called from another module. The other module must provide
configuration for AuthSignature from code, it doesn't support use
of the configuration directives.

```
put some perl here
```
