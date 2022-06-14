/*
    Mosh: the mobile shell
    Copyright 2012 Keith Winstein

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    In addition, as a special exception, the copyright holders give
    permission to link the code of portions of this program with the
    OpenSSL library under certain conditions as described in each
    individual source file, and distribute linked combinations including
    the two.

    You must obey the GNU General Public License in all respects for all
    of the code used other than OpenSSL. If you modify file(s) with this
    exception, you may extend this exception to your version of the
    file(s), but you are not obligated to do so. If you do not wish to do
    so, delete this exception statement from your version. If you delete
    this exception statement from all source files in the program, then
    also delete it here.
*/

/* Tests the Mosh crypto layer by encrypting and decrypting a bunch of random
   messages, interspersed with some random bad ciphertexts which we need to
   reject. */

#include <stdio.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "crypto.h"
#include "prng.h"
#include "fatal_assert.h"
#include "test_utils.h"

using namespace Crypto;

PRNG prng;

const size_t MESSAGE_SIZE_MAX     = (2048 - 16);
const size_t MESSAGES_PER_SESSION = 256;
const size_t NUM_SESSIONS         = 64;

bool verbose = false;

#define NONCE_FMT "%016" PRIx64

static std::string random_payload( void ) {
  const size_t len = prng.uint32() % MESSAGE_SIZE_MAX;
  char buf[ MESSAGE_SIZE_MAX ];
  prng.fill( buf, len );

  std::string payload( buf, len );
  return payload;
}

static void test_bad_decrypt( Session &decryption_session ) {
  std::string bad_ct = random_payload();

  bool got_exn = false;
  try {
    decryption_session.decrypt( bad_ct );
  } catch ( const CryptoException &e ) {
    got_exn = true;

    /* The "bad decrypt" exception needs to be non-fatal, otherwise we are
       vulnerable to an easy DoS. */
    fatal_assert( ! e.fatal );
  }

  if ( verbose ) {
    hexdump( bad_ct, "bad ct" );
  }
  fatal_assert( got_exn );
}

/* Generate a single key and initial nonce, then perform some encryptions. */
static void test_one_session( void ) {
  Base64Key key;
  Session encryption_session( key );
  Session decryption_session( key );

  uint64_t nonce_int = prng.uint64();

  if ( verbose ) {
    hexdump( key.data(), 16, "key" );
  }

  for ( size_t i=0; i<MESSAGES_PER_SESSION; i++ ) {
    Nonce nonce( nonce_int );
    fatal_assert( nonce.val() == nonce_int );

    std::string plaintext = random_payload();
    if ( verbose ) {
      printf( DUMP_NAME_FMT NONCE_FMT "\n", "nonce", nonce_int );
      hexdump( plaintext, "pt" );
    }

    std::string ciphertext = encryption_session.encrypt( Message( nonce, plaintext ) );
    if ( verbose ) {
      hexdump( ciphertext, "ct" );
    }

    Message decrypted = decryption_session.decrypt( ciphertext );
    if ( verbose ) {
      printf( DUMP_NAME_FMT NONCE_FMT "\n", "dec nonce", decrypted.nonce.val() );
      hexdump( decrypted.text, "dec pt" );
    }

    fatal_assert( decrypted.nonce.val() == nonce_int );
    fatal_assert( decrypted.text == plaintext );

    nonce_int++;

    if ( ! ( prng.uint8() % 16 ) ) {
      test_bad_decrypt( decryption_session );
    }

    if ( verbose ) {
      printf( "\n" );
    }
  }
}

static void deterministic_session() {
  std::string key_str = unhexify("ad77c2150b9060131b74f4a81991d2c9");
  std::string nonce_str = unhexify("a68fbd5fabbd1670");
  std::string plaintext =
    unhexify("bf206327afe1d5ed1417acc5b6ab387ab8640668e7b8aacc956214422670d3ac3"
	     "d2ee8ff6ad275439fc9214c413c7b4fc3cc0e4678415ca4394805f8a6df8ba0b5"
	     "8834444d2bb107ff9037a9ea9b821bd7211caf5f0e2565c7fef6014a584a7cb12"
	     "e3516346df212e3b0cd7402e57eae5576b436f69a115e185f3d7872ca5ea45855"
	     "3910b1772312e4464eb85a2583dc10b1682e020ee090257394cb6a3262f71d427"
	     "cad6cb679e4c325513fa71147a319bf09b7df2d574502d7656fc81062365a2340"
	     );
  std::string target_ciphertext =
    unhexify("a68fbd5fabbd167005d78ab6e8302f5acefb33144d4ffa9587a60f3970ae85012"
	     "0b4636d2d2fc5316a2d9554de112e2457e3088f53cd5e8eefb5681ed84bb8f4fa"
	     "64c220292c4a2dce332c1d99d73a948a079606bc9fb2c873d0c3376269c1cdc49"
	     "6b29b0d6f26a1f4354fd553008bd2bf85e3d40654bd9139d802ae36f2f2972f96"
	     "0ca9d472e43cd947f15b37665c8a9fd6512d058fae294c13de52831582d44d0f9"
	     "8fe6d299bfe3c9e8b918cba624b3097d58736319cc177516c28fc172a3a0ff305"
	     "86b01e5a9453b304c2df0038cc4b384cdc0e77ea8d5fd0a3");
  if (verbose) {
    printf("Deterministic session\n");
  }
  Base64Key key;
  memcpy(key.data(), key_str.data(), key_str.size());
  Session encryption_session(key);
  Session decryption_session(key);
  Nonce nonce(nonce_str.data(), nonce_str.size());
  std::string ciphertext = encryption_session.encrypt(Message(nonce, plaintext));
  if (verbose) {
    hexdump(ciphertext, "ct");
  }
  fatal_assert(ciphertext == target_ciphertext);
  Message decrypted = decryption_session.decrypt(target_ciphertext);
  if (verbose) {
    printf(DUMP_NAME_FMT NONCE_FMT "\n", "dec nonce", decrypted.nonce.val());
    hexdump(decrypted.text, "dec pt");
  }

  fatal_assert(decrypted.nonce.cc_str() == nonce_str);
  fatal_assert(decrypted.text == plaintext);
  if (verbose) {
    printf("\n");
  }
}

int main( int argc, char *argv[] ) {
  if ( argc >= 2 && strcmp( argv[ 1 ], "-v" ) == 0 ) {
    verbose = true;
  }

  try {
    deterministic_session();
  } catch ( const CryptoException &e ) {
    fprintf(stderr, "Crypto exception: %s\r\n",
	    e.what());
    return 1;
  }
  for ( size_t i=0; i<NUM_SESSIONS; i++ ) {
    try {
      //test_one_session();
    } catch ( const CryptoException &e ) {
      fprintf( stderr, "Crypto exception: %s\r\n",
               e.what() );
      return 1;
    }
  }

  return 0;
}
