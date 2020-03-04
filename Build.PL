use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
	module_name		=> 'Apache::Auth::Subrequest',
	license			=> 'ISC',
	dist_author		=> 'David Gwynne <dlg@uq.edu.au>',
	dist_version_from	=> 'lib/Apache/AuthSignature.pm',
	create_makefile_pl	=> 'small',
	requires => {
		'Net::SSH::Perl'	=> 2.14,
	},
	add_to_cleanup		=> [ 'Apache-AuthSignature-*' ],
);

$builder->create_build_script();
