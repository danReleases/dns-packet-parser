# Overall reading sources:
## https://routley.io/posts/hand-writing-dns-messages
## https://datatracker.ietf.org/doc/html/rfc1035
## https://www.netmeister.org/blog/dns-size.html

package Codemap;

use strict;
use warnings;

sub new {
    my $class = shift;

    my $codemap = {

# https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
        "opcode" => {
            "0" => "QUERY",
            "1" => "IQUERY",
            "2" => "STATUS",
            "4" => "NOTIFY",
            "5" => "UPDATE",
            "6" => "DSO",
        },

# https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
        ## N.B. Apparently there are 2 different params for 16, we will use the latest one
        "rcode" => {
            "0"  => "NOERROR",
            "1"  => "FORMERR",
            "2"  => "SERVFAIL",
            "3"  => "NXDOMAIN",
            "4"  => "NOTIMP",
            "5"  => "REFUSED",
            "6"  => "YXDOMAIN",
            "7"  => "YXRRSET",
            "8"  => "NXRRSET",
            "9"  => "NOTAUTH",
            "10" => "NOTZONE",
            "11" => "DSOTYPENI",
            "16" => "BADSIG",
            "17" => "BADKEY",
            "18" => "BADTIME",
            "19" => "BADMODE",
            "20" => "BADNAME",
            "21" => "BADALG",
            "22" => "BADTRUNC",
            "23" => "BADCOOKIE",
        },

# https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
        "qtype" => {

            # only implemented the mentioned record types in the question
            ## the list will to get too large otherwise
            "1"  => "A",
            "2"  => "NS",
            "5"  => "CNAME",
            "6"  => "SOA",
            "28" => "AAAA",
        },

# https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2
        "qclass" => {

            # only implemented the usual qclass values
            "1" => "IN",
            "3" => "CH",
            "4" => "HS",
        }
    };
    my $self = { "map" => $codemap };
    bless $self, $class;
}

sub get {
    my $self  = shift;
    my $tag   = shift;
    my $value = shift;

    my $mapped = "RESERVERD/UNASSIGNED";
    if (   defined( $self->{"map"}->{$tag} )
        && defined( $self->{"map"}->{$tag}->{$value} ) )
    {
        $mapped = $self->{"map"}->{$tag}->{$value};
    }
    return $mapped;
}

1;

package Helper;

use strict;
use warnings;

sub new {
    my $class = shift;
    my $self  = {};
    bless $self, $class;
}

# public
sub get_decimal {

    # https://www.oreilly.com/library/view/perl-cookbook/1565922433/ch02s05.html
    my $class  = shift;
    my $binary = shift;
    return unpack( "N", pack( "B32", substr( "0" x 32 . $binary, -32 ) ) );
}

sub compress_ipv6 {

    # source:
    ## https://metacpan.org/dist/Net-IP/source/IP.pm#L1529
    my $class = shift;
    my $ip    = shift;

    # Remove leading 0s: 0034 -> 34; 0000 -> 0
    $ip =~ s/
        (^|:)        # Find beginning or ':' -> $1
        0+           # 1 or several 0s
        (?=          # Look-ahead
        [a-fA-F\d]+  # One or several Hexs
        (?::|$))     # ':' or end
        /$1/gx;

    my $reg = '';

    # Find the longuest :0:0: sequence
    while (
        $ip =~ m/
        ((?:^|:)     # Find beginning or ':' -> $1
        0(?::0)+     # 0 followed by 1 or several ':0'
        (?::|$))     # ':' or end
        /gx
      )
    {
        $reg = $1 if ( length($reg) < length($1) );
    }

    # Replace sequence by '::'
    $ip =~ s/$reg/::/ if ( $reg ne '' );

    return $ip;
}

sub decode_A {

    # decodes binary content
    my $class  = shift;
    my $binary = shift;

    my $ip = [];
    foreach my $octet ( $binary =~ /(.{1,8})/g ) {
        $octet = Helper->get_decimal($octet);
        push @$ip, $octet;
    }
    return join( ".", @$ip );
}

sub decode_AAAA {

    # decodes binary content
    my $class  = shift;
    my $binary = shift;

    my $ip = [];
    foreach my $two_byte ( $binary =~ /(.{1,16})/g ) {
        my $octets = "";
        foreach my $octet ( $two_byte =~ /(.{1,4})/g ) {
            $octets .= sprintf( "%x", oct("0b$octet") );
        }
        push @$ip, $octets;
    }
    return Helper->compress_ipv6( join( ":", @$ip ) );
}

1;

package Packet;
our @ISA = "Helper";

use strict;
use warnings;

sub new {
    my $class = shift;
    my $hex   = shift;

    my $self = {
        "data" => [ split( //, $hex ) ],
        "ptr"  => 0,
    };

    bless $self, $class;
}

# public
sub read_nibbles {
    my $self       = shift;
    my $length     = shift;
    my $block_size = shift // 1;
    my $transform  = shift // "";

    my $data = "";
    while ( $length-- ) {
        my $val = "";
        $val .= $self->_next_nibble() foreach ( ( 1 .. $block_size ) );
        $val = hex($val);
        if ( $transform eq 'chr' ) {
            $val = chr($val);
        }
        elsif ( $transform eq 'bin' || $transform eq 'dec' ) {
            my $bin_format = "%0" . $block_size * 4 . "b";
            $val = sprintf( $bin_format, $val );
        }
        $data .= $val;
    }
    if ( $transform eq 'dec' ) {
        $data = Helper->get_decimal($data);
    }
    return $data;
}

sub peek_nibbles {

    # useful for debugging
    my $self  = shift;
    my $len   = shift // 1;
    my $start = shift // $self->{"ptr"};

    my $end = scalar @{ $self->{"data"} } - 1;
    $start = 0 if ( $start < 0 );
    $end   = $start + $len - 1
      if ( $len > 0 && ( $start + $len - 1 ) <= $end );
    return join( "", @{ $self->{"data"} }[ $start .. $end ] );
}

# private
sub _next_nibble {
    my $self = shift;
    return $self->{"data"}->[ $self->{"ptr"}++ ];
}

1;

package main;

use strict;
use warnings;

my $packet;
my $mapper;
my $decoded_data = {};

sub get_header {
    my $header_str = ";; ->>HEADER<<- ";

    my $length_map = [
        [ "id",      4, "dec" ],
        [ "flags",   4, "bin" ],
        [ "qdcount", 4, "dec" ],
        [ "ancount", 4, "dec" ],
        [ "nscount", 4, "dec" ],
        [ "arcount", 4, "dec" ],
    ];
    my $flags_map = [

        # https://www.freesoft.org/CIE/RFC/2065/40.htm
        [ "qr",    1 ], [ "opcode", 4 ],
        [ "aa",    1 ], [ "tc",     1 ], [ "rd", 1 ], [ "ra", 1 ],
        [ "z",     1 ],
        [ "ad",    1 ], [ "cd", 1 ],
        [ "rcode", 4 ],
    ];
    foreach my $map (@$length_map) {
        my $val = $packet->read_nibbles( 4, 1, $map->[2] );
        if ( $map->[0] ne 'flags' ) {
            $decoded_data->{ $map->[0] } = $val;
        }
        else {

            # we need to parition on a bit basis
            my $index = 0;
            foreach my $f_map (@$flags_map) {
                my $f_val = substr( $val, $index, $f_map->[1] );
                $f_val = Helper->get_decimal($f_val);
                $decoded_data->{ $f_map->[0] } = $f_val;
                $index += $f_map->[1];
            }

        }
    }

    my $opcode = $mapper->get( "opcode", $decoded_data->{"opcode"} );
    my $status = $mapper->get( "rcode",  $decoded_data->{"rcode"} );
    my $id     = $decoded_data->{"id"};
    $header_str .= "opcode: $opcode, status: $status, id: $id";
    $header_str .= "\n";

    my $flags = [];
    foreach (qw/qr aa tc rd ra ad cd z/) {

        # as I couldn't find a source on the order of the flags in the response,
        # the order of flags is based on personal observations on dig responses
        push( @$flags, $_ )
          if ( defined( $decoded_data->{$_} ) && $decoded_data->{$_} == 1 );
    }
    $flags = join( " ", @$flags );
    $header_str .= ";; flags: $flags; ";

    my $counts = [
        "QUERY: $decoded_data->{qdcount}",
        "ANSWER: $decoded_data->{ancount}",
        "AUTHORITY: $decoded_data->{nscount}",
        "ADDITIONAL: $decoded_data->{arcount}",
    ];
    $header_str .= join( ", ", @$counts );

    return $header_str;
}

sub get_question {
    my $query = [ "", "", "" ];

    $query->[0] .= read_domain();

    my $qtype = $packet->read_nibbles( 4, 1, "dec" );
    $query->[2] .= $mapper->get( "qtype", $qtype );

    my $qclass = $packet->read_nibbles( 4, 1, "dec" );
    $query->[1] .= $mapper->get( "qclass", $qclass );

    return ";; QUESTION SECTION:\n;" . join( "\t", @$query );
}

sub get_answer {
    my $max_records = $decoded_data->{ancount} + $decoded_data->{nscount};
    my $records     = [];
    while ( scalar @$records < $max_records ) {
        my $record =
          [ "", "", "", "", "" ];

        my $domain = read_domain();
        $record->[0] .= $domain;

        my $type = $packet->read_nibbles( 4, 1, "dec" );
        $type = $mapper->get( "qtype", $type );
        $record->[3] .= $type;

        my $class = $packet->read_nibbles( 4, 1, "dec" );
        $class = $mapper->get( "qclass", $class );
        $record->[2] .= $class;

        $packet->read_nibbles(4);    # ignore extra nibbles (00 00)

        my $ttl = $packet->read_nibbles( 4, 1, "dec" );
        $record->[1] .= $ttl;

        my $rdlength         = $packet->read_nibbles( 4, 1, "dec" );
        my $rdlength_nibbles = $rdlength * 2;

        my $content = "";
        $content = $packet->read_nibbles( $rdlength_nibbles, 1, "bin" )
          unless ( $type =~ /(CNAME|SOA)/ );
        if ( $type eq 'CNAME' ) {
            $content = read_domain();
        }
        elsif ( $type eq 'SOA' ) {
            my $soa_content = [];

            push @$soa_content, read_domain();
            push @$soa_content, read_domain();

            foreach ( ( 1 .. 5 ) ) {
                push @$soa_content,
                  Helper->get_decimal( $packet->read_nibbles( 8, 1, "bin" ) );
            }

            $content = join( " ", @$soa_content );
        }
        elsif ( $type eq 'A' ) {
            $content = Helper->decode_A($content);
        }
        elsif ( $type eq 'AAAA' ) {
            $content = Helper->decode_AAAA($content);
        }
        $record->[4] .= $content;

        push @$records, join( "\t", @$record );
        last if ( $packet->{"ptr"} == scalar @{ $packet->{"data"} } );
    }

    my $sections = [];
    if ( $decoded_data->{ancount} > 0 ) {
        my $answer_records = [];
        foreach ( ( 1 .. $decoded_data->{ancount} ) ) {
            push( @$answer_records, shift @$records );
        }
        push @$sections,
          ";; ANSWER SECTION:\n" . join( "\n", @$answer_records );
    }
    if ( $decoded_data->{nscount} > 0 ) {
        my $auth_records = [];
        foreach ( ( 1 .. $decoded_data->{nscount} ) ) {
            push( @$auth_records, shift @$records );
        }
        push @$sections,
          ";; AUTHORITY SECTION:\n" . join( "\n", @$auth_records );
    }
    return join( "\n\n", @$sections );
}

sub read_domain {
    return join( ".", @{ read_domain_arr() } ) . ".";
}

sub read_domain_arr {
    my $offset = shift;

    $packet->{"ptr"} = $offset if ( defined($offset) );

    my $qname_labels = [];
    while (1) {

        # check for compression offset
        my $qname_len;
        my $nibbles = $packet->read_nibbles( 2, 1, "bin" );
        if ( substr( $nibbles, 0, 2 ) eq '11' ) {

            # if the first 2 bits are one's, we need to offset

            # read the next 2 nibbles, which are a part of the offset
            $nibbles .= $packet->read_nibbles( 2, 1, "bin" );

            # set current ptr
            my $prev_ptr = $packet->{"ptr"};

            # read from offset
            my $offset = Helper->get_decimal( substr( $nibbles, 2 ) );

            # offset is in bytes, convert to nibbles (1 byte = 2 nibbles)
            my $offset_nibbles = $offset * 2;

            # recurse
            push @$qname_labels, @{ read_domain_arr($offset_nibbles) };

            # return back
            $packet->{"ptr"} = $prev_ptr;

            return $qname_labels;
        }
        else {
            # read domain label as normal
            $qname_len = Helper->get_decimal($nibbles);
            if ( $qname_len == 0 ) {

                # null byte, end reading label
                return $qname_labels;
            }
            push( @$qname_labels,
                $packet->read_nibbles( $qname_len, 2, "chr" ) );
        }
    }
}

# Boilerplate for reading perl input
sub ltrim {
    my $str = shift;
    $str =~ s/^\s+//;
    return $str;
}

sub rtrim {
    my $str = shift;
    $str =~ s/\s+$//;
    return $str;
}

my $hex = shift;
chomp($hex);

# Start
$packet = new Packet($hex);
$mapper = new Codemap();

my $header   = get_header();
my $question = get_question();
my $answer   = get_answer();

print STDOUT "$header\n\n$question\n\n$answer";

1;
