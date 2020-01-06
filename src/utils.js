import crypto from 'crypto'
import address_validator from '@swyftx/api-crypto-address-validator'
import BN from "bn.js";
import scrypt from "scrypt-js";
import elliptic from 'elliptic';
import keccak256 from 'js-sha3';
const Secp256k1 = elliptic.ec('secp256k1'); 
import blake2 from 'blakejs';
import bech32 from 'bech32'

var enc = new TextEncoder();

//BASE OPERATIONS

//BASE58
function base58encode (value, leeding_zeros, ripple) {
	var b58chars = bitcoinB58chars
	if (ripple){
		b58chars = rippleB58chars
	}
	var result = ''

	while (!value.isZero()) {
		var r = value.divmod(new BN(58))
		result = b58chars[r.mod] + result
		value = r.div
	}
	for (var i = 0; i < leeding_zeros ; i++) {
		result = b58chars[0] + result
	}
	return result
}

function base58decode(b58str){
    var b58chars_values = bitcoinB58charsValues;
    var value = new BN(0);
    for (var c in b58str){
        if (! b58chars_values.hasOwnProperty(b58str[c])){
            throw("Invalid character: "+b58str[c])
        }
        value = value.mul(new BN(58)).add(new BN(b58chars_values[b58str[c]]))
    }
    return (value)
}

const bitcoinB58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
var bitcoinB58charsValues = {}
for (var i in bitcoinB58chars) {
  bitcoinB58charsValues[bitcoinB58chars[i]] = parseInt(i)
}
const rippleB58chars = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz'
var rippleB58charsValues = {}
for (var i in rippleB58chars) {
  rippleB58charsValues[rippleB58chars[i]] = parseInt(i)
}

//BASE256
function base256decode(bytestr) {
    var value = new BN(0);
    var leeding_zeros = 0;
    var started = false;
    for (var b in bytestr) {
        if (bytestr[b] == 0 && !started){
            leeding_zeros +=1;
        }
        else{
            started = true
        }
        value = value.mul(new BN(256)).add(new BN(bytestr[b]));
    }
    return {value:value, leeding_zeros:leeding_zeros};
}
function base256decode_nocount(bytestr) {
    var a;
    a = base256decode(bytestr)
    return a.value
}

//BECH32
var ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

// pre-compute lookup table
var ALPHABET_MAP = {}
for (var z = 0; z < ALPHABET.length; z++) {
  var x = ALPHABET.charAt(z)

  if (ALPHABET_MAP[x] !== undefined) throw new TypeError(x + ' is ambiguous')
  ALPHABET_MAP[x] = z
}

function polymod (values) {
  var b ;
  var chk = new BN("1")
  var ff = new BN("07ffffffff",16)
  var n0 = new BN("98f2bc8e61",16)
  var n1 = new BN("79b76d99e2",16)
  var n2 = new BN("f33e5fb3c4",16)
  var n3 = new BN("ae2eabe2a8",16)
  var n4 = new BN("1e4f43e470",16)
  for (var i = 0 ; i < values.length; i++){
      b = chk.ushrn(35)
      chk = chk.uand(ff).ushln(5).uxor(new BN(values[i]))
      if(b & 1)
        chk = chk.uxor(n0)
      if(b & 2)
        chk = chk.uxor(n1)
      if(b & 4)
        chk = chk.uxor(n2)
      if(b & 8)
        chk = chk.uxor(n3)
      if(b & 16)
        chk = chk.uxor(n4)

  }
  return chk
}

function prefixChk (prefix) {
  var a = [];
  for (var i = 0; i < prefix.length; ++i) {
    var c = prefix.charCodeAt(i)
    if (c < 33 || c > 126) return 'Invalid prefix (' + prefix + ')'
    a.push(c & 0x1f)
    
  }
  a.push(0);
  return a
}

function encode_bech (prefix, data, LIMIT) {
	LIMIT = LIMIT || 90
	if ((prefix.length + 9 + data.length) > LIMIT) 
		throw new TypeError('Exceeds length limit')

	prefix = prefix.toLowerCase()
	// determine chk mod

	let words = bech32.toWords(new Uint8Array(data));
	var chk = polymod(prefixChk(prefix).concat(words).concat([0,0,0,0,0,0,0,0]))
	chk =chk.uxor(new BN(1))
	if (typeof chk === 'string')
		throw new Error(chk)

	var result = prefix + ':'
	for (var i = 0; i < words.length; ++i) {
		var x = words[i]
		if ((x >> 5) !== 0) throw new Error('Non 5-bit word')
		result += ALPHABET.charAt(x)
	}

	for (i = 0; i < 8; ++i) {
		var s = ((7 - i) * 5);
		chk.ushrn(s)
		var v = chk.ushrn(s).uand(new BN(31)).toNumber()
		result += ALPHABET.charAt(v)
	}
	return result
}


//END BASE OPERATIONS


function verify_solo_check(string, size)
{
    var raw = string.slice(0, -size);
    var h = crypto.createHash('sha256').update(crypto.createHash('sha256').update(raw).digest()).digest().toString("hex"); 
    var b = new BN(h, 16, "le");
    var b58 = new BN(58);
    var check = b.mod(b58.pow(new BN(size)));
    var b58check = base58encode(check, false)
    b58check = bitcoinB58chars[0].repeat(size-b58check.length) + b58check
    return b58check == string.slice(-size);
}

function recompute_private_key(secret1_b58_buff, secret2_b58_buff, progress_function, error_function){
    var salt = enc.encode("");

    var N = 16384;
    var r = 8;
    var p = 8;
    var dkLen = 32;
    var value = 0;
    return new Promise(resolve => {
        scrypt(secret1_b58_buff, salt, N, r, p, dkLen, function(error, progress, key1) {
            if (error) {
                error_function(error);
            } else if (key1) {
                scrypt(secret2_b58_buff, salt, N, r, p, dkLen, function(error, progress, key2) {
                    if (error) {
                        error_function(error);
                    } else if (key2) {
                        var k1bn = base256decode_nocount(key1);
                        var k2bn = base256decode_nocount(key2);
                        var sumofkey = k1bn.add(k2bn);
                        var privatekeynum = sumofkey.mod(Secp256k1.n);
                        var pair = Secp256k1.keyFromPrivate(privatekeynum.toString(16), "hex");
                        //following line seems useless but it is not!
                        resolve(pair);
                    } else {
                        // update UI
                        value = parseInt(progress * 50 + 50);
                        progress_function(value)
                    }
                });
            } else {
                // update UI
                value = parseInt(progress * 50);
                progress_function(value);
            }
        });
    });
}

function compute_wif_privkey(private_key, crypto_cur){
	var n ;
    if (crypto_cur == "LTC"){
		n = 176;
	}	
    else if (crypto_cur == "BTC" || crypto_cur == "BCH"){
		n = 128;
	}
	else{
		throw(crypto_cur + " wif format not supported");
	}
	var privbuf = new Uint8Array(34);
	var privwif256buf = new Uint8Array(38);
	privbuf.set([n],0);
	privbuf.set([1],33);
	privbuf.set(private_key.toArray(),1);
	var sha2 = crypto.createHash('sha256').update(crypto.createHash('sha256').update(privbuf).digest()).digest();
	privwif256buf.set(privbuf,0);
	privwif256buf.set(sha2.slice(0,4),34);
	var num;
	num = base256decode(privwif256buf);
	return base58encode(num.value, num.leeding_zeros);
}

function raise_if_bad_address(address, cryptocur, error_function){
	var res = false;
	if (cryptocur === "BCH"){
		res = address_validator.validate(address, cryptocur, 'prod', ['cashaddr']);
	}
	else{
		res = address_validator.validate(address, cryptocur);
	}
    if (res == false){
		error_function();
		throw ("Address Invalid");
    }
}

function compute_address(public_key, crypto_cur){
    if (crypto_cur == "BTC"){
        var pbuf = new Uint8Array(21);
        var address_b256 = new Uint8Array(25);
        var sha = crypto.createHash('sha256').update(new Uint8Array(public_key.encode("array",true))).digest();
        pub_key_hash = crypto.createHash('rmd160').update(sha).digest();
        pbuf.set([0],0);
        pbuf.set(pub_key_hash,1);
        var sha2 = crypto.createHash('sha256').update(crypto.createHash('sha256').update(pbuf).digest()).digest();
        address_b256.set(pbuf,0);
        address_b256.set(sha2.slice(0,4),21);
        var num;
        num = base256decode(address_b256);
        return base58encode(num.value, num.leeding_zeros);
    }
    if (crypto_cur == "LTC"){
        var pbuf = new Uint8Array(21);
        var address_b256 = new Uint8Array(25);
        var sha = crypto.createHash('sha256').update(new Uint8Array(public_key.encode("array",true))).digest();
        pub_key_hash = crypto.createHash('rmd160').update(sha).digest();
        pbuf.set([48],0);
        pbuf.set(pub_key_hash,1);
        var sha2 = crypto.createHash('sha256').update(crypto.createHash('sha256').update(pbuf).digest()).digest();
        address_b256.set(pbuf,0);
        address_b256.set(sha2.slice(0,4),21);
        var num;
        num = base256decode(address_b256);
        return base58encode(num.value, num.leeding_zeros);

    }
    if (crypto_cur == "BCH"){
        var sha = crypto.createHash('sha256').update(new Uint8Array(public_key.encode("array",true))).digest();
        pub_key_hash = crypto.createHash('rmd160').update(sha).digest();
        var pbuf = new Uint8Array(21);
        pbuf.set([0],0);
        pbuf.set(pub_key_hash,1);
        return encode_bech('bitcoincash', pbuf);

    }
    if (crypto_cur == "XRP"){
        var pbuf = new Uint8Array(21);
        var address_b256 = new Uint8Array(25);
        var sha = crypto.createHash('sha256').update(new Uint8Array(public_key.encode("array",true))).digest();
        pub_key_hash = crypto.createHash('rmd160').update(sha).digest();
        pbuf.set([0],0);
        pbuf.set(pub_key_hash,1);
        var sha2 = crypto.createHash('sha256').update(crypto.createHash('sha256').update(pbuf).digest()).digest();
        address_b256.set(pbuf,0);
        address_b256.set(sha2.slice(0,4),21);
        var num;
        num = base256decode(new Uint8Array(address_b256));
        return base58encode(num.value, num.leeding_zeros, true);
    }
    if (crypto_cur == "XTZ"){

        var pbuf = new Uint8Array(23);
        var address_b256 = new Uint8Array(27);
        var pub_key_hash = blake2.blake2b(new Uint8Array(public_key.encode("array",true)), "", 20);
        pbuf.set([6, 161, 161],0);
        pbuf.set(pub_key_hash,3);
        var sha2 = crypto.createHash('sha256').update(crypto.createHash('sha256').update(pbuf).digest()).digest();
        address_b256.set(pbuf,0);
        address_b256.set(sha2.slice(0,4),23);
        var num;
        num = base256decode(address_b256);
        return base58encode(num.value, num.leeding_zeros);
    }
    if (crypto_cur == "ETH"){
        var pbuf = public_key.encode("array",false).slice(1,65);
        return "0x"+keccak256.keccak256(pbuf).slice(24);
    }
}


export {raise_if_bad_address, verify_solo_check, recompute_private_key, compute_address, base58decode, base58encode, compute_wif_privkey};




