package PHP::MySQL_Session;

use strict;
use vars qw($VERSION);
$VERSION = 0.1;

use vars qw(%SerialImpl);
%SerialImpl = (
    php => 'PHP::Session::Serializer::PHP',
);

use DBI;
use Digest::MD5;
use UNIVERSAL::require;

sub _croak { require Carp; Carp::croak(@_) }

sub new {
    my($class, $sid, $opt) = @_;
    my %default = (
	database          => 'sessions',
    table             => 'sessions',
    userid            => 'phpsession',
    password          => 'phpsession',
    host              => '127.0.0.1',
	serialize_handler => 'php',
    session_life      => 1800,
	create            => 0,
    );
    $opt ||= {};
    my $self = bless {
	%default,
	%$opt,
	_sid  => $sid,
	_data => {},
    _expiry => "",
    }, $class;
    if ($self->{create} == 1) { $self->_create_session;  }
    $self->_validate_sid;
    $self->_parse_session;
    return $self;
}

# accessors, public methods

sub id { shift->{_sid} }

sub get {
    my($self, $key) = @_;
    return $self->{_data}->{$key};
}

sub set {
    my($self, $key, $value) = @_;
    $self->{_data}->{$key} = $value;
}

sub unregister {
    my($self, $key) = @_;
    delete $self->{_data}->{$key};
}

sub unset {
    my $self = shift;
    $self->{_data} = {};
}

sub is_registered {
    my($self, $key) = @_;
    return exists $self->{_data}->{$key};
}

sub decode {
    my($self, $data) = @_;
    $self->serializer->decode($data);
}

sub encode {
    my($self, $data) = @_;
    $self->serializer->encode($data);
}

sub save {
    my $self = shift;
    $self->_db_connect;
    my $encoded_data = $self->encode($self->{_data});
    my $sql = "UPDATE $self->{database} SET expiry='$self->{_expiry}', value='$encoded_data' WHERE sesskey='$self->{_sid}';";
	my $sth = $self->{_dbh}->prepare( $sql );
	$sth->execute() or _croak("can't update session table: $DBI::errstr");;
    $sth->finish();
    $self->_db_disconnect;
}

sub destroy {
    my $self = shift;
    $self->_db_connect;
    my $encoded_data = $self->encode($self->{_data});
    my $sql = "DELETE FROM $self->{database} WHERE sesskey='$self->{_sid}';";
	my $sth = $self->{_dbh}->prepare( $sql );
	$sth->execute();
    $sth->finish();
    $self->_db_disconnect;   
}

# private methods

sub _create_session {
    my $self = shift;
    my $length = 32;
    $self->_db_connect;
    $self->{_sid} = substr(Digest::MD5::md5_hex(Digest::MD5::md5_hex(time(). {}. rand(). $$)), 0, $length);
    $self->{_expiry} = time() + $self->{session_life};
    my $sql = "INSERT INTO $self->{database} (sesskey, expiry, value) VALUES ('$self->{_sid}','$self->{_expiry}','');";
	my $sth = $self->{_dbh}->prepare( $sql );
	$sth->execute() or _croak("create session failed. $DBI::errstr", $self->id);;
    $sth->finish();
    $self->_db_disconnect;
}

sub _validate_sid {
    my $self = shift;
    my($id) = $self->id =~ /^([0-9a-zA-Z]*)$/; # untaint
    defined $id or _croak("Invalid session id: ", $self->id);
    $self->{_sid} = $id;
}

sub _parse_session {
    my $self = shift;
    $self->_db_connect;
    my $sql = "SELECT * FROM $self->{database} WHERE sesskey = '$self->{_sid}'";
	my $sth = $self->{_dbh}->prepare( $sql );
	$sth->execute() or _croak("Session parsing failed: $DBI::errstr", $self->id);
    my $data = $sth->fetchrow_hashref();
    $sth->finish();
    $self->{_data} = $self->decode($data->{value});
    $self->{_expiry} = $data->{expiry};
    ## Update The Expire Time
    $self->_update_expiry;
    $self->_db_disconnect;
}

sub _update_expiry {
    my $self = shift;
    $self->{_expiry} = time() + $self->{session_life};
    my $sql = "UPDATE $self->{database} SET expiry = '$self->{_expiry}' WHERE sesskey = '$self->{_sid}';";
	my $sth = $self->{_dbh}->prepare( $sql );
	$sth->execute() or _croak("Updating session life failed: $DBI::errstr", $self->id);
    $sth->finish();
}

sub serializer {
    my $self = shift;
    my $impl = $SerialImpl{$self->{serialize_handler}};
    $impl->require;
    return $impl->new;
}

sub _db_connect {
    my $self = shift;
	$self->{_dbh} = DBI->connect("DBI:mysql:database=$self->{database};host=$self->{host}", $self->{userid}, $self->{password}) or
        _croak("Database connection failed : $DBI::errstr", $self->id);
}

sub _db_disconnect {
    my $self = shift;
    $self->{_dbh}->disconnect();
}

1;
__END__

=head1 NAME

PHP::MySQL_Session - read / write PHP session stored on a MySQL database

=head1 SYNOPSIS

  use PHP::MySQL_Session;

  my $session = PHP::MySQL_Session->new($id);

  # session id
  my $id = $session->id;

  # get/set session data
  my $foo = $session->get('foo');
  $session->set(bar => $bar);

  # remove session data
  $session->unregister('foo');

  # remove all session data
  $session->unset;

  # check if data is registered
  $session->is_registered('bar');

  # save session data
  $session->save;

  # destroy session
  $session->destroy;

  # create session file, if not existent
  $session = PHP::MySQL_Session->new($new_sid, { create => 1 });

=head1 DESCRIPTION

PHP::MySQL_Session provides a way to read / write PHP4 session data stored on a MySQL database, with
which you can make your Perl application session shared with PHP4.

If you like Apache::Session interface for session management, there is
a glue for Apache::Session of this module, Apache::Session::PHP.

=head1 OPTIONS

Constructor C<new> takes some options as hashref.

=over 4

=item database

database where session table lives. default: C<sessions>.

=item table

database table where session data is stored. default: C<sessions>.

=item userid

MySQL user id. default: C<phpsession>.

=item password

MySQL password. default: C<phpsession>.

=item host

MySQL server host address. default: C<127.0.0.1>.

=item serialize_handler

type of serialization handler. Currently only PHP default
serialization is supported.

=item create

whether to create a session record, if it's not existent yet. default: 0

=back

=head1 NOTES

=over 4

=item *

Array in PHP is hash in Perl.

=item *

Objects in PHP are restored as objects blessed into
PHP::Session::Object (Null class) and original class name is stored in
C<_class> key.


=item *

Not tested so much, thus there may be some bugs in
(des|s)erialization code. If you find any, tell me via email.

=back

=head1 AUTHOR

Mark Mitchell E<lt>mark@lapcrew.comE<gt>

Based on PHP::Session by
Tatsuhiko Miyagawa E<lt>miyagawa@bulknews.netE<gt>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 SEE ALSO

L<Apache::Session::PHP>, L<WDDX>, L<Apache::Session>, L<CGI::kSession>

=cut
