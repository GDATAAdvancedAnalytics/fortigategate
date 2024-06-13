#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha256);
use Crypt::AuthEnc::GCM;

sub module_constraints { [[0, 256], [24, 24], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $iv   = shift // random_hex_string (24);
  my $ct   = shift;

  my $key = sha256($word);
  my $iv_bin = pack ("H*", $iv);
  my $pt;

  #printf "key %08x,$key";
  
  #printf "iv: %08x\n",$iv;
  #printf "word %08x,$word";

  if (defined $ct) {
    my $ct_bin = pack ("H*", $ct);
    my $aes = Crypt::AuthEnc::GCM->new ("AES", $key, $iv_bin);
    $pt = $aes->decrypt_add($ct_bin);
  }
  else
  {
    $pt = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
  }
  
  #printf "hi: %s\n",unpack ("H*",$iv_bin);

  my $aes = Crypt::AuthEnc::GCM->new ("AES", $key, $iv_bin);
  my $ct_bin = $aes->encrypt_add ($pt);
  my $ct_cut = substr($ct_bin, 0, 8);
  my $hash = sprintf ('234647424b7c347c000000000000000000000000000000000000%s00000000000000000000000000000000%s', $iv, unpack ("H*", $ct_cut));

  return $hash;

}

sub module_verify_hash
{
  my $line = shift;

  my ($hash_in, $word) = split ":", $line;

  my $sig = substr ($hash_in, 0, 16);
  my $iv  = substr ($hash_in, 52, 24);
  my $ct = substr ($hash_in, 108, 16);

  return unless $sig eq '234647424b7c347c';

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $iv, $ct);

  return ($new_hash, $word_packed);
}

1;
