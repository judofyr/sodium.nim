import strutils

{.passl:"-lsodium".}

proc sodium_bin2hex(
  hex: ptr cchar, hex_maxlen: csize,
  bin: ptr cuchar, bin_len: csize
):ptr cchar {.importc: "sodium_bin2hex".}

proc sodium_hex2bin(
  bin: ptr cuchar, bin_maxlen: csize,
  hex: ptr cchar, hex_len: csize,
  ignore: ptr cchar, bin_len: ptr csize,
  hex_end: ptr ptr cchar
):cint {.importc: "sodium_hex2bin".}

proc crypto_sign_keypair(
  pk: ptr cuchar, sk: ptr cuchar
):cint {.importc: "crypto_sign_keypair"}

proc crypto_sign_detached(
   sig: ptr cuchar, siglen: ptr culonglong,
   m: ptr cuchar, mlen: culonglong,
   sk: ptr cuchar
):cint {.importc: "crypto_sign_detached".}

proc crypto_sign_verify_detached(
  sig: ptr cuchar,
  m: ptr cuchar, mlen: culonglong,
  pk: ptr cuchar
):cint {.importc: "crypto_sign_verify_detached".}

proc crypto_sign_ed25519_sk_to_pk(
  pk: ptr cuchar, sk: ptr cuchar
):cint {.importc: "crypto_sign_ed25519_sk_to_pk".}

const
  sign_BYTES = 64
  sign_PUBLICKEYBYTES = 32
  sign_SECRETKEYBYTES = 64

type
  RawArray[T;N:static[int]] = array[0..N-1, T]
  SignKey* = object
    hasSecret*: bool
    pk: RawArray[cuchar, sign_PUBLICKEYBYTES]
    sk: RawArray[cuchar, sign_SECRETKEYBYTES]

  Signature* = object
    data: RawArray[cuchar, sign_BYTES]

proc `$`[T: RawArray](data: var T):string =
  let
    len = high(T)+1
    hexlen = len*2
  result = newString(hexlen)
  let
    cres = cast[ptr cchar](cstring(result))
    cdata = cast[ptr cuchar](addr(data))
  discard sodium_bin2hex(cres, hexlen, cdata, len)

proc loadHex[T: RawArray](data: var T, str: string) =
  let
    len = high(T)+1
    hexlen = len*2

  doAssert(str.len == hexlen)

  let
    chex = cast[ptr cchar](cstring(str))
    cdata = cast[ptr cuchar](addr(data))

  discard sodium_hex2bin(cdata, len, chex, hexlen, nil, nil, nil)

proc public*(key: var SignKey):string =
  $key.pk

proc secret*(key: var SignKey):string =
  doAssert(key.hasSecret)
  $key.sk

proc loadPublic*(key: var SignKey, hex: string) =
  loadHex(key.pk, hex)
  key.hasSecret = false

proc loadSecret*(key: var SignKey, hex: string) =
  var
    sk = cast[ptr cuchar](addr(key.sk))
    pk = cast[ptr cuchar](addr(key.pk))
  loadHex(key.sk, hex)
  doAssert(crypto_sign_ed25519_sk_to_pk(pk, sk) == 0)
  key.hasSecret = true

proc generate*(key: var SignKey) =
  var
    sk = cast[ptr cuchar](addr(key.sk))
    pk = cast[ptr cuchar](addr(key.pk))
  doAssert(crypto_sign_keypair(pk, sk) == 0)
  key.hasSecret = true

proc `$`*(sig: var Signature):string =
  $sig.data

proc sign*(key: var SignKey, msg: string, sig: var Signature) =
  doAssert(key.hasSecret)
  var
    rawsig = cast[ptr cuchar](addr(sig.data))
    sk = cast[ptr cuchar](addr(key.sk))
    cmsg = cast[ptr cuchar](cstring(msg))
    mlen = culonglong(msg.len)
  doAssert(crypto_sign_detached(rawsig, nil, cmsg, mlen, sk) == 0)

proc verify*(key: var SignKey, msg: string, sig: var Signature):bool =
  var
    rawsig = cast[ptr cuchar](addr(sig.data))
    pk = cast[ptr cuchar](addr(key.pk))
    cmsg = cast[ptr cuchar](cstring(msg))
    mlen = culonglong(msg.len)
  crypto_sign_verify_detached(rawsig, cmsg, mlen, pk) == 0

when isMainModule:
  var key: SignKey
  generate(key)

  var pkey: SignKey
  pkey.loadPublic(key.public)

  var sig: Signature
  sign(key, "123", sig)
  echo "Signature: ", sig
  assert(verify(pkey, "123", sig))

