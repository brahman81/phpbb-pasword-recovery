#!/usr/bin/perl
#
#   Author: Tom Llewellyn-Smith <tom@onixconsulting.co.uk>
#   Copyright: © Onix Consulting Limited 2012-2013. All rights reserved.
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
use strict;
use warnings;
use Authen::Passphrase::PHPass;

$| = 1;
my $phpbb_creds_file = 'phpbb_users.txt';
my $dictionary_file = 'passwords.txt';

open(my $creds, '<', $phpbb_creds_file) or warn "error: $!\n";
open(my $dict, '<', $dictionary_file) or warn "error: $!\n";

while (<$creds>) {
    my $start = time();
    # username : hash
    my ($username,$hash) = m#^([\w,\s]+)? : (\$H\$9.*)$#;
    # print username so we know something is going on
    print "processing: $username\n";
    # preserve original hash
    my $original_hash = $hash;
    # replace hash prefix letter to be $P
    $hash =~ s#^\$H#\$P#;
    my $modified_hash = Authen::Passphrase::PHPass->from_crypt($hash);
    # seek to begining of password file
    seek($dict,0,0);
    while (<$dict>) {
        # remove newline
        my $current_pass = $_;
        chomp($current_pass);
        my $password_hash = Authen::Passphrase::PHPass->new(
            cost => $modified_hash->cost, salt => $modified_hash->salt,
            passphrase => $current_pass
        );
        my $computed_hash = '$H$' . 9 . $password_hash->salt . $password_hash->hash_base64;
        if ($computed_hash eq $original_hash) {
            # we have found a password!!! WooHooo!!!
            print "success: $username : $current_pass\n";
            last;
        }
    }
    my $end = time();
    my $total = $end - $start;
    print "completed in: " . $total . " seconds\n";
}
close($creds);
close($dict);
