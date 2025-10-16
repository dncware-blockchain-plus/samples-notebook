'use strict';
var version = "3.8.0";


var assert = require('assert');
var crypto = require('crypto');

function concatUint8Arrays(arr) {
    check_args({ uint8array: arr });
    return Buffer.concat(arr);
}

function composeUint8Arrays(arr) {
    check_args({ uint8array: arr });
    var header = Buffer.alloc(4 * (arr.length + 1));
    header.writeUInt32LE(arr.length, 0);
    for (var i = 0; i < arr.length; i++) {
        header.writeUInt32LE(arr[i].length, 4 * (i + 1));
    }
    return concatUint8Arrays([header, ...arr]);
}

function decomposeUint8Arrays(bytes) {
    if (bytes instanceof ArrayBuffer) {
        bytes = Buffer.from(bytes);
    }
    check_args({ buffer: { bytes } });
    var arr = [];
    var byteLength = bytes.length;
    var length = bytes.readUInt32LE(0);
    var offset = 4 * (length + 1);
    if (offset > byteLength) throw new RangeError();
    for (var i = 0; i < length; i++) {
        var l = bytes.readUInt32LE(4 * (i + 1));
        if (offset + l > byteLength) throw new RangeError();
        arr[i] = bytes.subarray(offset, offset + l);
        offset += l;
    }
    if (byteLength !== offset) throw new RangeError();
    return arr;
}



if (typeof window === 'undefined') { // Node.js
    var tobuffer = function(ab) {
        assert(ab instanceof ArrayBuffer);
        return Buffer.from(ab);
    };
} else {
    var tobuffer = function(ab) {
        assert(ab instanceof ArrayBuffer);
        return new Uint8Array(ab);
    };
}

function makeRandomUint8Array(len) {
    check_args({ length: { len } });
    var bytes = new Uint8Array(len);
    var buffer = bytes.buffer;
    for (var offset = 0; offset < len; offset += length) {
        var length = Math.min(65536, len - offset);
        crypto.getRandomValues(new Uint8Array(buffer, offset, length));
    }
    assert(offset === len);
    return tobuffer(buffer);
}

async function sha256() {
    check_args({ uint8array: arguments });
    if (1 !== arguments.length) {
        var len = 0;
        for (var i = 0; i < arguments.length; i++) {
            len += arguments[i].length;
        }
        var data = new Uint8Array(len);
        var offset = 0;
        for (var i = 0; i < arguments.length; i++) {
            data.set(arguments[i], offset);
            offset += arguments[i].length;
        }
    } else {
        var data = arguments[0];
    }
    var ab = await crypto.subtle.digest({ name: "SHA-256" }, data);
    return tobuffer(ab);
}

async function getBytesByPBKDF2(password, salt, iterations, len) {
    check_args({ uint8array: { password, salt }, length: { iterations, len } });
    var masterKey = await crypto.subtle.importKey('raw', password, { name: 'PBKDF2' }, false, ['deriveBits']);
    var algorithm = { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' };
    var ab = await crypto.subtle.deriveBits(algorithm, masterKey, len * 8);
    return tobuffer(ab);
}

async function getAESkeyByPBKDF2(password, salt) {
    password = encodeUTF8(password);
    var iv;
    var bytes = await getBytesByPBKDF2(password, salt, 1000, 48);
    var k = bytes.slice(0, 32);
    iv = bytes.slice(32, 48);
    var key = await crypto.subtle.importKey('raw', k, { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']);
    return { key, iv };
}

async function encryptAES(data, password, salt) {
    check_args({ uint8array: { data, salt }, string: { password } });
    var { key, iv } = await getAESkeyByPBKDF2(password, salt);
    var ab = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, data);
    return tobuffer(ab);
}

async function decryptAES(data, password, salt) {
    check_args({ uint8array: { data, salt }, string: { password } });
    var { key, iv } = await getAESkeyByPBKDF2(password, salt);
    var ab = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, key, data);
    return tobuffer(ab);
}

function get_hash(type) {
    switch (type) {
        case 'P-256':
        case 'ES256':
        case 'RS256':
            return { name: 'SHA-256' };
        case 'P-384':
        case 'ES384':
        case 'RS384':
            return { name: 'SHA-384' };
        case 'P-521':
        case 'ES512':
        case 'RS512':
            return { name: 'SHA-512' };
    }
    throw new Error('unrecognized type: ' + type);
}

async function generateECDSAKey(namedCurve) {
    check_args({ string: { namedCurve } });
    var algo = { name: 'ECDSA', namedCurve };
    var { privateKey, publicKey } = await crypto.subtle.generateKey(algo, true, ['sign']);
    var jwk = await crypto.subtle.exportKey('jwk', privateKey);
    return jwk;
}

async function generateRSAKey(modulusLength, hash) {
    check_args({ length: { modulusLength }, string: { hash } });
    var publicExponent = new Uint8Array([1, 0, 1]);
    hash = get_hash(hash);
    var algo = { name: 'RSASSA-PKCS1-v1_5', modulusLength, publicExponent, hash };
    var { privateKey, publicKey } = await crypto.subtle.generateKey(algo, true, ['sign']);
    var jwk = await crypto.subtle.exportKey('jwk', privateKey);
    return jwk;
}

async function importPrivateKey(key) {
    check_args({ object: { key } });
    if (key.kty === 'EC') {
        var { crv, x, y, d } = key;
        var keydata = { kty: 'EC', crv, ext: false, key_ops: ['sign'], x, y, d };
        var hash = get_hash(crv);
        var algo = { name: 'ECDSA', namedCurve: crv, hash };
        return { algo, key: await crypto.subtle.importKey('jwk', keydata, algo, false, ['sign']) };
    }
    if (key.kty === 'RSA') {
        var { alg, n, e, p, q, qi, d, dp, dq } = key;
        var keydata = { kty: 'RSA', alg, ext: false, key_ops: ['sign'], n, e, p, q, qi, d, dp, dq };
        var hash = get_hash(alg);
        var algo = { name: 'RSASSA-PKCS1-v1_5', hash };
        return { algo, key: await crypto.subtle.importKey('jwk', keydata, algo, false, ['sign']) };
    }
    throw new Error('unrecognized key format');
}

async function importPublicKey(key) {
    check_args({ object: { key } });
    if (key.kty === 'EC') {
        var { crv, x, y } = key;
        var keydata = { kty: 'EC', crv, ext: true, key_ops: ['verify'], x, y };
        var hash = get_hash(crv);
        var algo = { name: 'ECDSA', namedCurve: crv, hash };
        return { algo, key: await crypto.subtle.importKey('jwk', keydata, algo, true, ['verify']) };
    }
    if (key.kty === 'RSA') {
        var { alg, n, e } = key;
        var keydata = { kty: 'RSA', alg, ext: true, key_ops: ['verify'], n, e };
        var hash = get_hash(alg);
        var algo = { name: 'RSASSA-PKCS1-v1_5', hash };
        return { algo, key: await crypto.subtle.importKey('jwk', keydata, algo, true, ['verify']) };
    }
    throw new Error('unrecognized key format');
}

var rphead = [0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00];

async function importPublicKeyFromRsaPem(pem) {
    check_args({ string: { pem } });
    var { type, bytes } = decodePEM(pem);
    if (type === 'RSA PUBLIC KEY') {
        var head = new Uint8Array(rphead);
        var len = bytes.length + 1;
        head[21] = (len >> 8);
        head[22] = (len & 255);
        var len = bytes.length + 20;
        head[2] = (len >> 8);
        head[3] = (len & 255);
        var keydata = concatUint8Arrays([head, bytes]);
    } else if (type === 'PUBLIC KEY') {
        var keydata = bytes;
    } else {
        throw new Error('unexpected PEM header');
    }
    var algo = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
    return { algo, key: await crypto.subtle.importKey('spki', keydata, algo, true, ['verify']) };
}

async function signSignature(privateKey, data) {
    check_args({ object: { privateKey }, uint8array: { data } });
    var { algo, key } = privateKey;
    var ab = await crypto.subtle.sign(algo, key, data);
    return tobuffer(ab);
}

async function verifySignature(publicKey, data, signature) {
    check_args({ object: { publicKey }, uint8array: { data, signature } });
    var { algo, key } = publicKey;
    return crypto.subtle.verify(algo, key, signature, data);
}



var http = require('http');
var https = require('https');

var keepAliveAgentHttp = new http.Agent({ keepAlive: true });
var keepAliveAgentHttps = new https.Agent({ keepAlive: true });

function callHTTP(method, url, bytes = Buffer.alloc(0), options = {}, cancel) {
    check_args({ string: { method, url }, buffer: { bytes } });
    return new Promise((resolve, reject) => {
        var { rawResponse } = options;
        options = Object.assign({}, options);
        options.method = method;
        options.headers = Object.assign({}, options.headers);
        Object.assign(options.headers, {
            'Content-Type': 'application/octet-stream',
            'Content-Length': bytes.length,
        });
        if (url.startsWith("http://")) {
            options.agent = options.agent || keepAliveAgentHttp;
            var error = new Error();
            var req = http.request(url, options, callback);
        } else if (url.startsWith("https://")) {
            options.agent = options.agent || keepAliveAgentHttps;
            var error = new Error();
            var req = https.request(url, options, callback);
        } else {
            throw new Error("invalid url");
        }
        req.on('error', error_handler);
        req.write(bytes);
        req.end();
        if (cancel) add_cancel_listener(cancel, abort);

        function abort(err) {
            reject(err);
            req.destroy();
        }

        function error_handler(err) {
            reject(err);
            if (cancel) remove_cancel_listener(cancel, abort);
        }

        function callback(res) {
            res.on('error', error_handler);
            var list = [];
            res.on('data', chunk => list.push(chunk));
            res.on('end', () => {
                if (cancel) remove_cancel_listener(cancel, abort);
                try {
                    var buf = Buffer.concat(list);
                    if (res.statusCode !== 200) {
                        error.message = (res.statusCode + ': ' + buf.toString());
                        reject(error);
                    } else if (rawResponse) {
                        resolve(buf);
                    } else {
                        resolve(JSON.parse(buf.toString()));
                    }
                } catch (err) {
                    reject(err);
                }
            });
        }

    });
}


function isPositiveInteger(x) {
    return Number.isInteger(x) && 1 <= x;
}

function check_args(list) {
    assert(typeof list === 'object');
    for (var type of Object.keys(list)) {
        var args = list[type];
        assert(typeof args === 'object');
        var typeS = type.split('_');
        for (var n of Object.keys(args)) {
            if (args[n] === undefined && typeS[1] === 'opt') continue;
            switch (typeS[0]) {
                case 'string':
                    if (typeof args[n] !== 'string') throw new Error(`argument "${n}" is not a string`);
                    break;
                case 'boolean':
                    if (typeof args[n] !== 'boolean') throw new Error(`argument "${n}" is not boolean`);
                    break;
                case 'uint8array':
                    if (!(args[n] instanceof Uint8Array)) throw new Error(`argument "${n}" is not an instanceof Uint8Array`);
                    break;
                case 'buffer':
                    if (!(args[n] instanceof Buffer)) throw new Error(`argument "${n}" is not an instanceof Buffer`);
                    break;
                case 'length':
                    if (args[n] < 0) throw new Error(`argument "${n}" is negative`);
                    if (!Number.isInteger(args[n])) throw new Error(`argument "${n}" is not an integer`);
                    break;
                case 'array':
                    if (!Array.isArray(args[n])) throw new Error(`argument "${n}" is not an array`);
                    break;
                case 'object':
                    if (typeof args[n] !== 'object' || !args[n]) throw new Error(`argument "${n}" is not an object`);
                    break;
                case 'promise':
                    if (!(args[n] instanceof Promise)) throw new Error(`argument "${n}" is not a promise`);
                    break;
                case 'function':
                    if (typeof args[n] !== 'function') throw new Error(`argument "${n}" is not a function`);
                    break;
                default:
                    assert(!"known type");
            }
        }
    }
}



function isValidUnicodeString(str) {
    if (typeof str !== 'string') return false;
    for (var ch of str) {
        if (ch.length >= 2) continue;
        var c = ch.charCodeAt(0);
        if (0xd800 <= c && c <= 0xdfff) return false;
    }
    return true;
}

function encodeUTF8(str) { // intentionally ignores surrogate pair
    check_args({ string: { str } });
    var bytes = new Uint8Array(str.length * 3);
    var j = 0;
    for (var i = 0; i < str.length; i++) {
        var c = str.charCodeAt(i);
        if (c <= 0x007F) {
            bytes[j++] = c;
        } else if (c <= 0x07FF) {
            bytes[j++] = (0xC0 + ((c >> 6) & 0x1F));
            bytes[j++] = (0x80 + (c & 0x3F));
        } else {
            bytes[j++] = (0xE0 + ((c >> 12) & 0x0F));
            bytes[j++] = (0x80 + ((c >> 6) & 0x3F));
            bytes[j++] = (0x80 + (c & 0x3F));
        }
    }
    return bytes.slice(0, j);
}

function decodeUTF8(bytes) {
    check_args({ uint8array: { bytes } });
    var list = [];
    var codes = [];
    for (var i = 0; i < bytes.length; i++) {
        var o1 = bytes[i];
        if ((o1 & 0x80) === 0) {
            var c = o1;
        } else if ((o1 & 0xE0) === 0xC0) {
            var o2 = bytes[++i];
            if ((o2 & 0xC0) !== 0x80) throw new Error(`unexpected byte at ${i}`);
            var c = ((o1 & 0x1F) << 6) + (o2 & 0x3F);
            if (c <= 0x007F) throw new Error(`unexpected byte at ${i}`);
        } else if ((o1 & 0xF0) === 0xE0) {
            var o2 = bytes[++i];
            if ((o2 & 0xC0) !== 0x80) throw new Error(`unexpected byte at ${i}`);
            var o3 = bytes[++i];
            if ((o3 & 0xC0) !== 0x80) throw new Error(`unexpected byte at ${i}`);
            var c = ((o1 & 0x0F) << 12) + ((o2 & 0x3F) << 6) + (o3 & 0x3F);
            if (c <= 0x07FF) throw new Error(`unexpected byte at ${i}`);
        } else {
            throw new Error(`unexpected byte at ${i}`);
        }
        codes.push(c);
        if (codes.length >= 512) {
            list.push(String.fromCharCode.apply(null, codes));
            codes = [];
        }
    }
    list.push(String.fromCharCode.apply(null, codes));
    return list.join('');
}

var alphabetBase16 = '0123456789abcdef';
var alphabetBase16_cap = '0123456789ABCDEF';
var lookupBase16 = {};
for (var i = 0; i < 16; i++) {
    lookupBase16[alphabetBase16[i]] = i;
    lookupBase16[alphabetBase16_cap[i]] = i;
}

function encodeBase16(bytes) {
    check_args({ uint8array: { bytes } });
    return encodeBaseX(bytes, 4, alphabetBase16);
}

function decodeBase16(str) {
    check_args({ string: { str } });
    return decodeBaseX(str, 4, lookupBase16);
}

var alphabetBase32 = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
var lookupBase32 = {};
for (var i = 0; i < 32; i++) {
    lookupBase32[alphabetBase32[i]] = i;
}

function encodeBase32(bytes, padding = false) {
    check_args({ uint8array: { bytes }, boolean: { padding } });
    return encodeBaseX(bytes, 5, alphabetBase32, padding);
}

function decodeBase32(str) {
    check_args({ string: { str } });
    return decodeBaseX(str, 5, lookupBase32);
}

var alphabetBase64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
var lookupBase64 = {};
for (var i = 0; i < 64; i++) {
    lookupBase64[alphabetBase64[i]] = i;
}

function encodeBase64(bytes, padding = false) {
    check_args({ uint8array: { bytes } });
    return encodeBaseX(bytes, 6, alphabetBase64, padding);
}

function decodeBase64(str) {
    check_args({ string: { str } });
    return decodeBaseX(str, 6, lookupBase64);
}

var alphabetBase64url = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
var lookupBase64url = {};
for (var i = 0; i < 64; i++) {
    lookupBase64url[alphabetBase64url[i]] = i;
}

function encodeBase64url(bytes, padding = false) {
    check_args({ uint8array: { bytes }, boolean: { padding } });
    return encodeBaseX(bytes, 6, alphabetBase64url, padding);
}

function decodeBase64url(str) {
    check_args({ string: { str } });
    return decodeBaseX(str, 6, lookupBase64url);
}

var alphabetBase57 = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
var lookupBase57 = {};
for (var i = 0; i < 57; i++) {
    lookupBase57[alphabetBase57[i]] = i;
}

function encodeBase57(bytes) {
    check_args({ uint8array: { bytes } });
    return encodeBaseY(bytes, 57, alphabetBase57);
}

function decodeBase57(str) {
    check_args({ string: { str } });
    return decodeBaseY(str, 57, lookupBase57);
}

function encodeBaseX(bytes, bc, alphabet, padding) {
    var list2 = [];
    var list = [];
    var x = 0;
    var bits = 0;
    var mask = (1 << bc) - 1;
    for (var i = 0; i < bytes.length; i++) {
        x = (x << 8) | bytes[i];
        bits += 8;
        while (bits >= bc) {
            var y = (x >> (bits - bc)) & mask;
            list.push(alphabet[y]);
            bits -= bc;
        }
        x &= mask;
        if (list.length >= 128) {
            list2.push(list.join(''));
            list = [];
        }
    }
    if (bits > 0) {
        x = (x << 8);
        bits += 8;
        var y = (x >> (bits - bc)) & mask;
        list.push(alphabet[y]);
        bits -= bc;
    }
    if (padding) {
        while (bits > 0) {
            if (bits >= bc) {
                list.push('=');
                bits -= bc;
            } else {
                bits += 8;
            }
        }
    }
    list2.push(list.join(''));
    return list2.join('');
}

function decodeBaseX(str, bc, lookup) {
    var bytes = new Uint8Array(str.length);
    var j = 0;
    var x = 0;
    var bits = 0;
    for (var i = 0; i < str.length; i++) {
        var c = str[i];
        if (c === '=') {
            while (str[++i] === '=');
            if (i === str.length) break;
            throw new Error(`unexpected char at ${i}`);
        }
        var z = lookup[c];
        if (z == null) throw new Error(`unexpected char at ${i}`);
        x = (x << bc) | z;
        bits += bc;
        if (bits >= 8) {
            var y = (x >> (bits - 8)) & 255;
            bytes[j++] = y;
            bits -= 8;
        }
        x &= 255;
    }
    return bytes.slice(0, j);
}

function bignum_add(x, y, n) {
    var z = [];
    var c = 0;
    for (var i = 0; i < x.length || i < y.length || c; i++) {
        var a = (x[i] >>> 0) + (y[i] >>> 0) + c;
        for (c = 0; a >= n; c++) {
            a -= n;
        }
        z[i] = a;
    }
    return z;
}

function bignum_mul(x, k, n) {
    var z = [];
    var c = 0;
    for (var i = 0; i < x.length || c; i++) {
        var a = (x[i] >>> 0) * k + c;
        var r = a % n;
        c = (a - r) / n;
        z[i] = r;
    }
    return z;
}

function bignum_change_base(x, m, n) {
    var z = [0];
    var y = [1];
    for (var i = 0; i < x.length; i++) {
        var a = bignum_mul(y, x[i], n);
        z = bignum_add(z, a, n);
        y = bignum_mul(y, m, n);
    }
    return z;
}

function encodeBaseY(arr, n, alphabet) {
    var arr = Array.from(arr);
    arr.push(1);
    var a = bignum_change_base(arr, 256, n);
    return a.map(e => alphabet[e]).join('');
}

function decodeBaseY(str, n, lookup) {
    var a = Array.from(str).map((c, i) => {
        var z = lookup[c];
        if (z == null) throw new Error(`unexpected char at ${i}`);
        return z;
    });
    var b = bignum_change_base(a, n, 256);
    if (b.pop() !== 1) throw new Error(`invalid format`);
    return Uint8Array.from(b);
}

function encodePEM(bytes, type) {
    check_args({ uint8array: { bytes }, string: { type } });
    var b64 = encodeBase64(bytes, true);
    var list = [];
    list.push(`-----BEGIN ${type}-----`);
    for (var offset = 0; offset < b64.length; offset += 64) {
        list.push(b64.slice(offset, offset + 64));
    }
    list.push(`-----END ${type}-----`);
    return list.join('\n');
}

function decodePEM(str) {
    check_args({ string: { str } });
    var rex = /^\s*-+BEGIN ([^-]+)-+([^-]*)-+END ([^-]+)-+\s*$/;
    var m = rex.exec(str);
    if (!m) throw new Error('unrecognized PEM format');
    if (m[1] !== m[3]) throw new Error('mismatched header and footer');
    var b64 = m[2].replace(/\s/g, '');
    return { type: m[1], bytes: decodeBase64(b64) };
}

function makeRandomText(len) {
    check_args({ length: { len } });
    var bytes = makeRandomUint8Array(len);
    var list = [];
    for (var i = 0; i < bytes.length; i++) {
        list.push(alphabetBase57[bytes[i] % 57]);
    }
    return list.join('');
}



/*
abstract Signing Wallet interface
    wallet.config
    wallet.address
    wallet.publicData
    wallet.sign(bytes) _async

abstract Verifying Wallet interface
    wallet.config
    wallet.address
    wallet.verify(bytes, signature) _async
*/

var _ethers;
var _xmldsigjs;

function setEthersModule(mod) {
    _ethers = mod;
}

function setXmlDSigJsModule(mod) {
    _xmldsigjs = mod;
}

function load_xmldsigjs() {
    if (!_xmldsigjs) { // legacy support
        if (typeof window === 'undefined') { // Node.js
            _xmldsigjs = require('xmldsigjs');
        } else {
            _xmldsigjs = window.XmlDSigJs;
        }
    }
    if (!_xmldsigjs) throw new Error('XmlDSigJs not enabled: use api.setXmlDSigJsModule()');
    return _xmldsigjs;
}

async function getWalletAddress(config, publicData, chainID) {
    check_args({ string: { config }, uint8array: { publicData } });
    if (config === 'esth') {
        if (!_ethers) throw new Error('ethers not enabled');
        return _ethers.getAddress('0x' + encodeBase16(publicData));
    }
    if (config[1] === 's') {
        chainID = 'DNCWARE/BlockChain';
    } else {
        check_args({ string: { chainID } });
    }
    var bytes = await getBytesByPBKDF2(encodeUTF8(chainID), publicData, 10, 20);
    var b = concatUint8Arrays([new Uint8Array([1]), bytes]);
    return config[0] + encodeBase57(b);
}

function isValidWalletAddressFormat(address) {
    try {
        check_args({ string: { address } });
        if ('0x' === address.substring(0, 2)) {
            if (!_ethers) return false;
            if (!_ethers.isAddress(address)) return false;
            return address === _ethers.getAddress(address);
        }
        if (address[0] !== 'e' && address[0] !== 'r') return false;
        var b = decodeBase57(address.slice(1));
        if (b[0] !== 1) return false;
        if (b.length !== 21) return false;
        return true;
    } catch (err) {
        return false;
    }
}

async function generateWalletKey(config) {
    check_args({ string: { config } });
    var c = getWalletClass(config);
    return c._generateKey(config);
}

async function importSigningWallet(config, key, chainID) {
    check_args({ string: { config }, object: { key } });
    var c = getWalletClass(config);
    var wallet = new c(config);
    wallet._use = 'sign';
    if (key.external) {
        return (async () => {
            await wallet._openPrivate(key);
            await checkPublicKey(c, config, wallet.publicData);
            wallet.address = await getWalletAddress(config, wallet.publicData, chainID);
            return wallet;
        })();
    }
    await wallet._openPrivate(key);
    await checkPublicKey(c, config, wallet.publicData);
    wallet.address = await getWalletAddress(config, wallet.publicData, chainID);
    return wallet;
}

async function checkPublicKey(c, config, publicData) {
    var vw = new c(config);
    vw._use = 'verify';
    await vw._openPublic(publicData);
}

async function importVerifyingWallet(config, publicData, chainID) {
    check_args({ string: { config }, uint8array: { publicData } });
    var c = getWalletClass(config);
    var wallet = new c(config);
    wallet._use = 'verify';
    await wallet._openPublic(publicData);
    wallet.address = await getWalletAddress(config, publicData, chainID);
    return wallet;
}

class BaseWallet {
    constructor(config) {
        this.config = config;
    }

    async sign(bytes) {
        check_args({ uint8array: { bytes } });
        if (this._use !== 'sign') throw new Error('invalid operation');
        bytes = concatUint8Arrays([bytes, encodeUTF8(this.address)]);
        return this._sign(bytes);
    }

    async verify(bytes, signature) {
        check_args({ uint8array: { bytes, signature } });
        if (this._use !== 'verify') throw new Error('invalid operation');
        bytes = concatUint8Arrays([bytes, encodeUTF8(this.address)]);
        return this._verify(bytes, signature);
    }
}

function getWalletClass(config) {
    switch (config) {
        case 'r':
        case 'rs':
            return Wallet_r;
        case 'e':
        case 'es':
            return Wallet_e;
        case 'rj':
        case 'rsj':
            return Wallet_j;
        case 'rp':
        case 'rsp':
            return Wallet_p;
        case 'esth':
            return Wallet_eth;
    }
    throw new Error('invalid config');
}

function getWalletDescription(config) {
    var c = getWalletClass(config);
    if (config[1] === 's') {
        return `${config} (${c.description} universal chainID)`;
    } else {
        return `${config} (${c.description} locked chainID)`;
    }

}

var external_wallets = new Map();

function pluginExternalWalletModule(name, external) {
    external_wallets.set(name, external);
}

/*===================== RSA 2048; 160bits address; =====================*/

class Wallet_r extends BaseWallet {
    static get description() {
        return "RSA 2048; 160bits address;";
    }

    static async _generateKey(config) {
        return generateRSAKey(2048, 'RS256');
    }

    async _openPrivate(key) {
        if (key.external) {
            var external = external_wallets.get(key.external);
            if (!(external && external.importPublicData_r)) throw new Error('unknown external key');
            this.external = external;
            this._privateKey = key;
            return (async () => {
                this.publicData = await external.importPublicData_r(key);
                if (!(this.publicData instanceof Uint8Array)) throw new Error('protocol violation: importPublicData_r is expected to return a Uint8Array');
            })();
        }
        var { n, e, p, q, qi, d, dp, dq } = key;
        var publicData = decodeBase64url(n);
        if (publicData.length !== 256) throw new Error('invalid key length');
        if (e !== 'AQAB') throw new Error('invalid exponent');
        var jwk = { kty: 'RSA', alg: 'RS256', n, e, p, q, qi, d, dp, dq };
        this._privateKey = await importPrivateKey(jwk);
        this.publicData = publicData;
    }

    async _openPublic(publicData) {
        if (publicData.length !== 256) throw new Error('invalid key length');
        var n = encodeBase64url(publicData);
        var e = 'AQAB';
        var jwk = { kty: 'RSA', alg: 'RS256', n, e };
        this._publicKey = await importPublicKey(jwk);
    }

    async _sign(bytes) {
        if (this.external) {
            return (async () => {
                var data = await this.external.signSignature_r(this._privateKey, bytes);
                if (!(data instanceof Uint8Array)) throw new Error('protocol violation: signSignature_r is expected to return a Uint8Array');
                return data;
            })();
        }
        return signSignature(this._privateKey, bytes);
    }

    async _verify(bytes, signature) {
        return verifySignature(this._publicKey, bytes, signature);
    }
}

/*===================== EC P-256; 160bits address; =====================*/

class Wallet_e extends BaseWallet {
    static get description() {
        return "EC P-256; 160bits address;";
    }

    static _generateKey(config) {
        return generateECDSAKey('P-256');
    }

    async _openPrivate(key, chainID) {
        if (key.external) {
            var external = external_wallets.get(key.external);
            if (!(external && external.importPublicData_e)) throw new Error('unknown external key');
            this.external = external;
            this._privateKey = key;
            return (async () => {
                this.publicData = await external.importPublicData_e(key);
                if (!(this.publicData instanceof Uint8Array)) throw new Error('protocol violation: importPublicData_e is expected to return a Uint8Array');
            })();
        }
        var { x, y, d } = key;
        var bx = decodeBase64url(x);
        var by = decodeBase64url(y);
        if (bx.length !== 32) throw new Error('invalid key length');
        if (by.length !== 32) throw new Error('invalid key length');
        var jwk = { kty: 'EC', crv: 'P-256', x, y, d };
        this._privateKey = await importPrivateKey(jwk);
        var publicData = new Uint8Array(64);
        publicData.set(bx, 0);
        publicData.set(by, 32);
        this.publicData = publicData;
    }

    async _openPublic(publicData) {
        if (publicData.length !== 64) throw new Error('invalid key length');
        var x = encodeBase64url(publicData.slice(0, 32));
        var y = encodeBase64url(publicData.slice(32));
        var jwk = { kty: 'EC', crv: 'P-256', x, y };
        this._publicKey = await importPublicKey(jwk);
    }

    async _sign(bytes) {
        if (this.external) {
            return (async () => {
                var data = await this.external.signSignature_e(this._privateKey, bytes);
                if (!(data instanceof Uint8Array)) throw new Error('protocol violation: signSignature_e is expected to return a Uint8Array');
                return data;
            })();
        }
        return signSignature(this._privateKey, bytes);
    }

    async _verify(bytes, signature) {
        return verifySignature(this._publicKey, bytes, signature);
    }
}

/*===================== RSA 2048; 160bits address; JACIC XML signature =====================*/

class Wallet_j extends BaseWallet {
    static get description() {
        return "RSA 2048; 160bits address; custom XML signature;";
    }

    static async _generateKey(config) {
        return generateRSAKey(2048, 'RS256');
    }

    async _openPrivate(key) {
        if (key.external) {
            var external = external_wallets.get(key.external);
            if (!(external && external.importPublicData_j)) throw new Error('unknown external key');
            this.external = external;
            this._privateKey = key;
            return (async () => {
                this.publicData = await external.importPublicData_j(key);
                if (!(this.publicData instanceof Uint8Array)) throw new Error('protocol violation: importPublicData_j is expected to return a Uint8Array');
            })();
        }
        var { n, e, p, q, qi, d, dp, dq } = key;
        var publicData = decodeBase64url(n);
        if (publicData.length !== 256) throw new Error('invalid key length');
        if (e !== 'AQAB') throw new Error('invalid exponent');
        var jwk = { kty: 'RSA', alg: 'RS256', n, e, p, q, qi, d, dp, dq };
        this._privateKey = await importPrivateKey(jwk);
        this.publicData = publicData;
    }

    async _openPublic(publicData) {
        if (publicData.length !== 256) throw new Error('invalid key length');
        var n = encodeBase64url(publicData);
        var e = 'AQAB';
        var jwk = { kty: 'RSA', alg: 'RS256', n, e };
        this._publicKey = await importPublicKey(jwk);
    }

    async _sign(bytes) {
        var xml = `<envelop><txhash>${encodeBase64(await sha256(bytes))}</txhash></envelop>`;
        if (this.external) {
            return (async () => {
                var sxml = await this.external.signSignature_j(this._privateKey, xml);
                if (typeof sxml !== 'string') throw new Error('protocol violation: signSignature_j is expected to return a string');
                return encodeUTF8(sxml);
            })();
        }
        var XmlDSigJs = load_xmldsigjs();
        var hash = await sha256(encodeUTF8(xml));
        var signedinfo = `<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#Res0"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>${encodeBase64(hash,true)}</DigestValue></Reference></SignedInfo>`;
        var xmlCanonicalizer = new XmlDSigJs.XmlCanonicalizer(true, false);
        var e = xmlCanonicalizer.Canonicalize(XmlDSigJs.Parse(signedinfo));
        var data = encodeUTF8(e.replace(/^<SignedInfo [^>]*>/, '<SignedInfo>'));
        data = await sha256(data);
        var sigvalue = await signSignature(this._privateKey, data);
        var sxml = `<?xml version="1.0" encoding="UTF-8"?><SignedDocument><Object Id="Res0" dsig="http://www.w3c.org/2000/09/xmldsig#Object">${xml}</Object><Signature xmlns="http://www.w3.org/2000/09/xmldsig#">${signedinfo}<SignatureValue>${encodeBase64(sigvalue,true)}</SignatureValue></Signature></SignedDocument>`;
        return encodeUTF8(sxml);
    }

    async _verify(bytes, signature) {
        var XmlDSigJs = load_xmldsigjs();
        try {
            var { XmlCanonicalizer } = XmlDSigJs;
            var xml = `<envelop><txhash>${encodeBase64(await sha256(bytes))}</txhash></envelop>`;
            var doc = new DOMParser({
                locator: {},
                errorHandler: {
                    warning: function(w) {},
                    error: function(e) {}
                }
            }).parseFromString(decodeUTF8(signature), 'application/xml');
            var NS = 'http://www.w3.org/2000/09/xmldsig#';
            var sigelem = doc.getElementsByTagNameNS(NS, 'Signature')[0];
            if (!sigelem) return false;
            var signedinfo = GetFirstChild(sigelem, 'SignedInfo', NS);
            if (!signedinfo) return false;
            var sigvalue = GetFirstChild(sigelem, 'SignatureValue', NS);
            if (!sigvalue) return false;
            var reference = GetFirstChild(signedinfo, 'Reference', NS);
            if (!reference) return false;
            var digestvalue = GetFirstChild(reference, 'DigestValue', NS);
            if (!digestvalue) return false;
            var ref = await sha256(encodeUTF8(xml));
            var val = decodeBase64((digestvalue.innerHTML || digestvalue.firstChild).toString().replace(/\s/g, ''));
            if (ref.length !== val.length) return false;
            for (var i = 0; i < ref.length; i++) {
                if (ref[i] !== val[i]) return false;
            }
            var xmlCanonicalizer = new XmlCanonicalizer(true, false);
            var e = xmlCanonicalizer.Canonicalize(signedinfo);
            var data = encodeUTF8(e.replace(/^<SignedInfo [^>]*>/, '<SignedInfo>'));
            data = await sha256(data);
            var sigbytes = decodeBase64((sigvalue.innerHTML || sigvalue.firstChild).toString().replace(/\s/g, ''));
            return verifySignature(this._publicKey, data, sigbytes);
        } catch (err) {
            return false;
        }
    }
}

function GetFirstChild(node, name, NS) {
    for (var i = 0; i < node.childNodes.length; i++) {
        var child = node.childNodes[i];
        if (child.nodeType === 1 && child.localName === name && child.namespaceURI === NS) {
            return child;
        }
    }
}

/*===================== RSA general; 160bits address; =====================*/

class Wallet_p extends BaseWallet {
    static get description() {
        return "RSA general; 160bits address;";
    }

    static async _generateKey(config) {
        return generateRSAKey(2048, 'RS256');
    }

    async _openPrivate(key) {
        if (key.external) {
            var external = external_wallets.get(key.external);
            if (!(external && external.importPublicData_p)) throw new Error('unknown external key');
            this.external = external;
            this._privateKey = key;
            return (async () => {
                this.publicData = await external.importPublicData_p(key);
                if (!(this.publicData instanceof Uint8Array)) throw new Error('protocol violation: importPublicData_p is expected to return a Uint8Array');
            })();
        }
        var { n, e, p, q, qi, d, dp, dq } = key;
        var bin_n = decodeBase64url(n);
        var bin_e = decodeBase64url(e);
        if (bin_n.length < 256) throw new Error('invalid key length');
        if (bin_n.length > 1024) throw new Error('invalid key length');
        if (bin_e.length > 32) throw new Error('invalid exponent length');
        // PKCS1 encoding
        var publicData = new Uint8Array(11 + bin_n.length + bin_e.length);
        var idx = 0;
        publicData[idx++] = 0x30;
        publicData[idx++] = 0x82;
        var len = 7 + bin_n.length + bin_e.length;
        publicData[idx++] = (len >> 8);
        publicData[idx++] = (len & 255);
        publicData[idx++] = 0x02;
        publicData[idx++] = 0x82;
        var len = 1 + bin_n.length;
        publicData[idx++] = (len >> 8);
        publicData[idx++] = (len & 255);
        publicData[idx++] = 0;
        publicData.set(bin_n, idx);
        idx += bin_n.length;
        publicData[idx++] = 0x02;
        publicData[idx++] = bin_e.length;
        publicData.set(bin_e, idx);
        idx += bin_e.length;
        assert(idx === publicData.length);
        var jwk = { kty: 'RSA', alg: 'RS256', n, e, p, q, qi, d, dp, dq };
        this._privateKey = await importPrivateKey(jwk);
        this.publicData = publicData;
    }

    async _openPublic(publicData) {
        try {
            var idx = 0;
            if (publicData[idx++] !== 0x30) throw 0;
            if (publicData[idx++] !== 0x82) throw 0;
            var len = publicData.length - 4;
            if (publicData[idx++] !== (len >> 8)) throw 0;
            if (publicData[idx++] !== (len & 255)) throw 0;
            if (publicData[idx++] !== 0x02) throw 0;
            if (publicData[idx++] !== 0x82) throw 0;
            var len = (publicData[idx++] << 8) + publicData[idx++];
            if (len > publicData.length - idx) throw 0;
            if (publicData[idx++] !== 0x00) throw 0;
            var bin_n = publicData.slice(idx, idx + len - 1);
            idx += bin_n.length;
            if (publicData[idx++] !== 0x02) throw 0;
            var len = publicData[idx++];
            if (len !== publicData.length - idx) throw 0;
            var bin_e = publicData.slice(idx, idx + len);
            idx += bin_e.length;
            assert(idx === publicData.length);
        } catch (err) {
            throw new Error('invalid format');
        }
        if (bin_n.length < 256) throw new Error('invalid key length');
        if (bin_n.length > 1024) throw new Error('invalid key length');
        if (bin_e.length > 32) throw new Error('invalid exponent length');
        var n = encodeBase64url(bin_n);
        var e = encodeBase64url(bin_e);
        var jwk = { kty: 'RSA', alg: 'RS256', n, e };
        this._publicKey = await importPublicKey(jwk);
    }

    async _sign(bytes) {
        if (this.external) {
            return (async () => {
                var data = await this.external.signSignature_p(this._privateKey, bytes);
                if (!(data instanceof Uint8Array)) throw new Error('protocol violation: signSignature_p is expected to return a Uint8Array');
                return data;
            })();
        }
        return signSignature(this._privateKey, bytes);
    }

    async _verify(bytes, signature) {
        return verifySignature(this._publicKey, bytes, signature);
    }
}

/*===================== ethereum wallet =====================*/

class Wallet_eth extends BaseWallet {
    static get description() {
        return "ethereum wallet; 160bits address;";
    }

    static async _generateKey(config) {
        if (!_ethers) throw new Error('ethers not enabled');
        return { x: _ethers.id(makeRandomText(31)) };
    }

    async _openPrivate(key) {
        if (key.external) {
            var external = external_wallets.get(key.external);
            if (!(external && external.importPublicData_eth)) throw new Error('unknown external key');
            this.external = external;
            this._privateKey = key;
            return (async () => {
                this.publicData = await external.importPublicData_eth(key);
                if (!(this.publicData instanceof Uint8Array)) throw new Error('protocol violation: importPublicData_eth is expected to return a Uint8Array');
            })();
        }
        if (!_ethers) throw new Error('ethers not enabled');
        var { x } = key;
        if (typeof x !== 'string') throw new Error('invalid key');
        var w = new _ethers.Wallet(x);
        this._privateKey = w;
        this.publicData = decodeBase16(w.address.substring(2));
    }

    async _openPublic(publicData) {
        if (publicData.length !== 20) throw new Error('invalid key length');
        this._publicKey = null;
    }

    async _sign(bytes) {
        var str = `DNCWARE/BlockChain+${encodeBase64(bytes, true)}`;
        if (this.external) {
            return (async () => {
                var data = await this.external.signSignature_eth(this._privateKey, str);
                if (!(data instanceof Uint8Array)) throw new Error('protocol violation: signSignature_eth is expected to return a Uint8Array');
                return data;
            })();
        }
        return (async () => {
            var data = await this._privateKey.signMessage(str);
            return decodeBase16(data.substring(2));
        })();
    }

    async _verify(bytes, signature) {
        if (!_ethers) throw new Error('ethers not enabled');
        var str = `DNCWARE/BlockChain+${encodeBase64(bytes, true)}`;
        try {
            return this.address == _ethers.verifyMessage(str, '0x' + encodeBase16(signature));
        } catch (err) {
            return false;
        }
    }

}



async function parseWalletFile(wf_stringified) {
    check_args({ string: { wf_stringified } });
    try {
        var wf = JSON.parse(wf_stringified);
        if (!(typeof wf === 'object' && wf)) throw new Error();
        if (!['3.0', '1.0'].includes(wf.version)) throw 'unsupported version';
        if (wf.chainID && !(typeof wf.chainID === 'string')) throw new Error();
        if (wf.name && !(typeof wf.name === 'string')) throw new Error();
        if (!(typeof wf.encrypted === 'string' && (wf.encrypted = decodeBase64(wf.encrypted)))) throw new Error();
        if (!(typeof wf.salt === 'string' && (wf.salt = decodeBase64(wf.salt)))) throw new Error();
    } catch (err) {
        if (typeof err === 'string') throw new Error(err);
        throw new Error('invalid file format');
    }
    wf.stringified = wf_stringified;
    return wf;
}

async function parseUnlockedWalletFile(uw_stringified) {
    check_args({ string: { uw_stringified } });
    try {
        var uwf = JSON.parse(uw_stringified);
        if (!(typeof uwf === 'object' && uwf)) throw new Error();
        if (!['3.0', '1.0'].includes(uwf.version)) throw 'invalid version';
        if (uwf.chainID && !(typeof uwf.chainID === 'string')) throw new Error();
        if (uwf.name && !(typeof uwf.name === 'string')) throw new Error();
        if (!(typeof uwf.config === 'string')) throw new Error();
        if (!(typeof uwf.key === 'object' && uwf.key)) throw new Error();
    } catch (err) {
        if (typeof err === 'string') throw new Error(err);
        throw new Error('file broken');
    }
    if (uwf.key.external) {
        return (async () => {
            var uw = await importSigningWallet(uwf.config, uwf.key, uwf.chainID);
            uw.stringified = uw_stringified;
            uw.chainID = uwf.chainID;
            return uw;
        })();
    }
    var uw = await importSigningWallet(uwf.config, uwf.key, uwf.chainID);
    uw.stringified = uw_stringified;
    uw.chainID = uwf.chainID;
    return uw;
}

async function unlockWalletFile(wf, password) {
    check_args({ object: { wf }, string: { password } });
    try {
        var decrypted = await decryptAES(wf.encrypted, password, wf.salt);
        var uw_stringified = decodeUTF8(decrypted);
        var uwf = JSON.parse(uw_stringified);
    } catch (err) {
        throw new Error('invalid password');
    }
    try {
        if (wf.version !== uwf.version) throw new Error();
        if (wf.chainID !== uwf.chainID) throw new Error();
        if (wf.name && wf.name !== uwf.name) throw new Error();
    } catch (err) {
        throw new Error('file defaced');
    }
    return parseUnlockedWalletFile(uw_stringified);
}

async function createWalletFile(name, password, config, chainID) {
    check_args({ string: { name, password, config } });
    var key = await generateWalletKey(config);
    return lockWalletFile(config, key, name, password, chainID);
}

async function lockWalletFile(config, key, name, password, chainID) {
    check_args({ string: { config, name, password } });
    if (config[1] === 's') {
        chainID = undefined;
    } else {
        check_args({ string: { chainID } });
    }
    var stringified = JSON.stringify({ version: '3.0', chainID, name, config, key });
    var salt = makeRandomUint8Array(20);
    var encrypted = await encryptAES(encodeUTF8(stringified), password, salt);
    var wf = { version: '3.0', chainID, name, encrypted: encodeBase64(encrypted), salt: encodeBase64(salt) };
    return JSON.stringify(wf, null, 4);
}



function makeHASH(chainID, bytes) {
    return getBytesByPBKDF2(encodeUTF8(chainID), bytes, 2, 32);
}

function makeTXID(hash) {
    return 'x' + encodeBase57(hash);
}

function isValidTXIDFormat(txid) {
    try {
        if (typeof txid !== 'string') return false;
        if (txid[0] !== 'x') return false;
        if (txid.length > 64) return false;
        var hash = decodeBase57(txid.slice(1));
        if (hash.length !== 32) return false;
    } catch (err) {
        return false;
    }
    return true;
}

function isValidDGAL(a) {
    if (!Array.isArray(a)) return false;
    for (var i = 0; i < a.length; i++) {
        var id = a[i];
        if (getTypeofId(id) !== 'contract' && !isUnifiedName(id)) return false;
    }
    return true;
}

function isValidDiscloseTo(a) {
    if (!Array.isArray(a)) return false;
    for (var i = 0; i < a.length; i++) {
        var id = a[i];
        if (!isMemberId(id) && !isUnifiedName(id)) return false;
    }
    return true;
}

function isValidRelateTo(a) {
    if (!Array.isArray(a)) return false;
    for (var i = 0; i < a.length; i++) {
        var id = a[i];
        if (!isRelateId(id) && !isUnifiedName(id)) return false;
    }
    return true;
}

async function createRequest(addr, contract, args = {}, options = {}) {
    if (typeof addr === 'string') addr = [addr];
    if (!Array.isArray(addr)) throw new Error('invalid addr');
    addr.forEach(a => { if (!isValidWalletAddressFormat(a)) throw new Error('invalid addr'); });
    if (addr.length === 0) throw new Error('no address');
    if (addr.length !== new Set(addr).size) throw new Error('duplicated address');
    if (getTypeofId(contract) !== 'contract' && !isUnifiedName(contract)) throw new Error('invalid contract');
    if (typeof args !== 'object' || args == null) throw new Error('invalid args');
    if (typeof options !== 'object' || options == null) throw new Error('invalid options');
    var { readmode, deadline = Date.now() + 100000, DGAL, discloseTo, relateTo, multisig, oracle = makeRandomText(16), blockref, attachments } = options;
    if (readmode !== undefined && !['full', 'local', 'fast'].includes(readmode)) throw new Error('invalid readmode');
    if (!isPositiveInteger(deadline)) throw new Error('invalid deadline');
    if (DGAL !== undefined && !isValidDGAL(DGAL)) throw new Error('invalid DGAL');
    if (discloseTo !== undefined && !isValidDiscloseTo(discloseTo)) throw new Error('invalid discloseTo');
    if (relateTo !== undefined && !isValidRelateTo(relateTo)) throw new Error('invalid relateTo');
    if (multisig !== undefined && !isPositiveInteger(multisig)) throw new Error('invalid multisig');
    if (typeof oracle !== 'string') throw new Error('invalid oracle');
    if (blockref !== undefined) {
        if (typeof blockref !== 'object' || blockref === null) throw new Error('invalid blockref');
        if (!isPositiveInteger(blockref.no)) throw new Error('invalid blockref number');
        try {
            var h = decodeBase64(blockref.hash);
            if (!(32 <= h.length && h.length <= 64)) throw 0;
        } catch (err) {
            throw new Error('invalid blockref encoding');
        }
    }
    if (attachments !== undefined) {
        if (!Array.isArray(attachments)) throw new Error('invalid attachments');
        for (var a of attachments) {
            if (typeof a !== 'string') throw new Error('invalid attachment');
            try {
                var b = decodeBase64(a);
            } catch (err) {
                throw new Error('invalid attachment hash encoding');
            }
            if (b.length !== 32) throw new Error('invalid attachment hash length');
        }
    }

    if (addr.length === 1) addr = addr[0];
    var reqbody = { contract, args, addr, readmode, deadline, DGAL, discloseTo, relateTo, multisig, oracle, blockref, attachments };
    var reqstr = JSON.stringify(reqbody);
    if (!isValidUnicodeString(reqstr)) throw new Error('invalid unicode string');
    var reqbin = encodeUTF8(reqstr);
    return { reqbin, signatures: [] };
}

async function signRequest(request, wallet, chainID) {
    check_args({ string: { chainID } });
    var { reqbin, signatures } = request;
    var { blockref } = parseRequest(reqbin);
    var hash = await makeHASH(chainID, reqbin);
    var hash2 = hash;
    if (blockref) {
        hash2 = concatUint8Arrays([hash, decodeBase64(blockref.hash)]);
    }
    if (wallet.external) {
        return (async () => {
            signatures.push([wallet.config, wallet.publicData, await wallet.sign(hash2)]);
        })();
    }
    signatures.push([wallet.config, wallet.publicData, await wallet.sign(hash2)]);
    return makeTXID(hash);
}

function parseRequest(reqbin) {
    var reqstr = decodeUTF8(reqbin);
    if (!isValidUnicodeString(reqstr)) throw new Error('invalid unicode string');
    var reqbody = JSON.parse(reqstr);
    var { contract, args, addr, readmode, deadline, DGAL, discloseTo, relateTo, multisig, oracle, blockref, attachments } = reqbody;
    if (typeof addr === 'string') reqbody.addr = addr = [addr];
    if (!Array.isArray(addr)) throw new Error('invalid addr');
    addr.forEach(a => { if (!isValidWalletAddressFormat(a)) throw new Error('invalid addr'); });
    if (addr.length === 0) throw new Error('no address');
    if (addr.length !== new Set(addr).size) throw new Error('duplicated addr');
    if (getTypeofId(contract) !== 'contract' && !isUnifiedName(contract)) throw new Error('invalid contract');
    if (typeof args !== 'object' || args === null) throw new Error('invalid args');
    if (readmode !== undefined && !['full', 'local', 'fast'].includes(readmode)) throw new Error('invalid readmode');
    if (!isPositiveInteger(deadline)) throw new Error('invalid deadline');
    if (DGAL !== undefined && !isValidDGAL(DGAL)) throw new Error('invalid DGAL');
    if (discloseTo !== undefined && !isValidDiscloseTo(discloseTo)) throw new Error('invalid discloseTo');
    if (relateTo !== undefined && !isValidRelateTo(relateTo)) throw new Error('invalid relateTo');
    if (multisig !== undefined && !isPositiveInteger(multisig)) throw new Error('invalid multisig');
    if (typeof oracle !== 'string') throw new Error('invalid oracle');
    if (blockref !== undefined) {
        if (typeof blockref !== 'object' || blockref === null) throw new Error('invalid blockref');
        if (!isPositiveInteger(blockref.no)) throw new Error('invalid blockref number');
        try {
            var h = decodeBase64(blockref.hash);
            if (!(32 <= h.length && h.length <= 64)) throw 0;
        } catch (err) {
            throw new Error('invalid blockref encoding');
        }
    }
    if (attachments !== undefined) {
        if (!Array.isArray(attachments)) throw new Error('invalid attachments');
        for (var a of attachments) {
            if (typeof a !== 'string') throw new Error('invalid attachment');
            try {
                var b = decodeBase64(a);
            } catch (err) {
                throw new Error('invalid attachment hash encoding');
            }
            if (b.length !== 32) throw new Error('invalid attachment hash length');
        }
    }
    return reqbody;
}

async function verifyRequestSignatures(addr, hash, signatures, chainID, blockref, multisig) {
    check_args({ string: { chainID } });
    if (!Array.isArray(addr)) throw new Error('invalid addr');
    if (!Array.isArray(signatures)) throw new Error('invalid signatures');
    var hash2 = hash;
    if (blockref) {
        hash2 = concatUint8Arrays([hash, decodeBase64(blockref.hash)]);
    }
    multisig = multisig || addr.length;
    var addrs = new Set(addr);
    var seen = new Set();
    for (var [config, publicData, signature] of signatures) {
        var wallet = await importVerifyingWallet(config, publicData, chainID);
        if (!await wallet.verify(hash2, signature)) throw new Error('inconsistent signature');
        if (addrs.has(wallet.address)) multisig--;
        if (seen.has(wallet.address)) throw new Error('duplicated signer');
        seen.add(wallet.address);
    }
    if (multisig > 0) throw new Error('insufficient signers');
}

function packRequest(request) {
    var { reqbin, signatures } = request;
    var arr = [new Uint8Array([3]), reqbin];
    for (var [config, publicData, signature] of signatures) {
        arr.push(encodeUTF8(config), publicData, signature);
    }
    return composeUint8Arrays(arr);
}

function unpackRequest(bytes) {
    check_args({ buffer: { bytes } });
    var arr = decomposeUint8Arrays(bytes);
    var i = 0;
    var version = arr[i++];
    if (version.length !== 1 || version[0] !== 3) throw new Error('unsupported version');
    var reqbin = arr[i++];
    var signatures = [];
    while (i < arr.length) {
        var config = decodeUTF8(arr[i++]);
        var publicData = arr[i++];
        var signature = arr[i++];
        signatures.push([config, publicData, signature]);
    }
    var request = { reqbin, signatures };
    return request;
}



function getTypeofId(id) {
    if (typeof id !== 'string') return;
    if (id.length > 50) return;
    switch (id[0]) {
        case 'a':
            if ('anonymous' === id) return 'user';
            break;
        case 'u':
            if (/^u\d{4,19}$/.test(id)) return 'user';
            break;
        case 'g':
            if (/^g\d{4,19}$/.test(id)) return 'group';
            break;
        case 'c':
            if (/^c\d{4,19}$/.test(id)) return 'contract';
            if (/^c1[a-z]{3,18}$/.test(id)) return 'contract';
            break;
        case 'd':
            if (/^d\d{4,19}$/.test(id)) return 'domain';
            if ('default' === id) return 'domain';
            break;
        case 'p':
            if (/^p\d{4,19}$/.test(id)) return 'peer';
            break;
        case 'x':
            if (isValidTXIDFormat(id)) return 'tx';
            break;
        case 'e':
        case 'r':
            if (isValidWalletAddressFormat(id)) return 'wallet';
            break;
    }
}

function isMemberId(id) {
    if (['user', 'group', 'contract'].includes(getTypeofId(id))) return true;
    return false;
}

function isObjectId(id) {
    if (['user', 'group', 'contract', 'domain', 'peer'].includes(getTypeofId(id))) return true;
    return false;
}

function isKeyword(id) {
    if (typeof id !== 'string') return false;
    if (['all', 'self', 'me', 'default', 'anonymous', 'local', 'this'].includes(id)) return true;
    return false;
}

function isRelateId(id) {
    if (typeof id !== 'string') return false;
    if (id === '') return false;
    if (id.length > 100) return false;
    if (/[^\w\-\/@+*=!#%&|:.?><]/.test(id)) return false;
    if (!isValidUnicodeString(id)) return false;
    return true;
}

function isAclGroupId(id) {
    if (typeof id !== 'string') return false;
    if (id.length > 12) return false;
    if (/^g1\d{8,8}$/.test(id)) return true;
    if (/^g1\d{10,10}$/.test(id)) return true;
    return false;
}

function isAclGroupMemberId(id) {
    if (['all', 'self'].includes(id)) return true;
    var type = getTypeofId(id);
    if (['user', 'contract', 'domain'].includes(type)) return true;
    if (type === 'group' && isAclGroupId(id)) return true;
    return false;
}

function isObjectName(name) {
    if (typeof name !== 'string') return false;
    if (name === '') return false;
    if (name.length > 20) return false;
    if (/['\\,\s@/;:\x00]/.test(name)) return false;
    if (!isValidUnicodeString(name)) return false;
    return true;
}

function isUnifiedName(name) {
    if (typeof name !== 'string') return false;
    if (name.length > 41) return false;
    var a = name.split('@');
    if (a.length !== 2) return false;
    return (isObjectName(a[0]) || a[0] === '') && isObjectName(a[1]);
}

function isStatusString(status) {
    if (typeof status !== 'string') return false;
    switch (status) {
        case 'ok':
        case 'canceled':
        case 'aborted':
        case 'denied':
        case 'thrown':
        case 'error':
        case 'read':
            return true;
    }
    return false;
}

function getHashAnchors(no) {
    var a = getHashAnchorsRel(no);
    return a.map(e => no - e);
}

function getHashAnchorsRel(no) {
    if (no <= 1) return [];
    for (var i = 0, j = 2; j < no; i++, j *= 2) {
        if (no % j) break;
    }
    if (i === 0) {
        return [1];
    }
    if (i <= 4) {
        return [Math.pow(2, i), 1];
    }
    for (var j = 3; i >= j * j; j++);
    for (var k = 2; i >= k * k * k * k; k++);
    assert(0 < j && j < i);
    assert(0 < k - 1 && k - 1 < i);
    assert(k - 1 < j);
    return [Math.pow(2, i), Math.pow(2, i - k + 1), Math.pow(2, i - j), 1];
}

async function calculateTxHash({ txid, pack, addr, txno, caller_txno = 0, caller, callee, argstr, subtxs, steps, status, valuestr, disclosed_to, related_to }) {
    assert(typeof txno === 'number');
    assert(typeof caller_txno === 'number');
    assert(typeof caller === 'string');
    assert(typeof callee === 'string');
    assert(typeof argstr === 'string');
    assert(typeof subtxs === 'number');
    assert(typeof steps === 'number');
    assert(typeof status === 'string');
    assert(typeof valuestr === 'string');
    if (disclosed_to instanceof Set) disclosed_to = [...disclosed_to];
    if (related_to instanceof Set) related_to = [...related_to];
    assert(Array.isArray(disclosed_to) && disclosed_to.every(e => typeof e === 'string'));
    assert(Array.isArray(related_to) && related_to.every(e => typeof e === 'string'));

    var a = [txno, caller_txno, caller, callee, subtxs, steps, status, disclosed_to, related_to];
    var h = await sha256(encodeUTF8(JSON.stringify(a)), encodeUTF8(argstr), encodeUTF8(valuestr));

    if (txid) { // main transaction
        assert(typeof txid === 'string');
        assert(pack instanceof Uint8Array);
        assert(typeof addr === 'string');
        var h = await sha256(pack, h);
        var h = await sha256(encodeUTF8(addr), h);
        var h = await sha256(encodeUTF8(txid), h);
    }
    return h;
}

async function calculateBlockHash({ blkno, time, seed, records, status, start_txno, end_txno }, tx_hashes, get_block_hash) {
    assert(typeof blkno === 'number');
    assert(typeof time === 'number');
    assert(typeof seed === 'string');
    assert(typeof records === 'number');
    assert(typeof status === 'string');
    assert(typeof start_txno === 'number');
    assert(typeof end_txno === 'number');
    assert(Array.isArray(tx_hashes) && tx_hashes.every(e => e instanceof Uint8Array));
    assert(tx_hashes.length === records);
    assert(typeof get_block_hash === 'function');

    var a = [blkno, time, seed, records, status, start_txno, end_txno];
    var h = await sha256(encodeUTF8(JSON.stringify(a) + ';'));

    var tx_hashesA = [];
    for (var i = 0; i < tx_hashes.length; i++) {
        var anchors = getHashAnchors(i + 1);
        var p = [tx_hashes[i]];
        for (var j of anchors) {
            p.push(tx_hashesA[j - 1]);
        }
        var hash = await sha256.apply(null, p);
        tx_hashesA[i] = hash;
    }

    var p = [h];
    if (hash) p.push(hash);
    if (blkno > 0) {
        var anchors = getHashAnchors(blkno);
        for (var j of anchors) {
            p.push(await get_block_hash(j));
        }
    }
    return await sha256.apply(null, p);
}



/*
abstract Socket interface
    async callHTTP(method, url, bytes, options, cancel)
    async call(bytes, spv)
    close()
*/

var cancel_listener_map = new WeakMap();

function add_cancel_listener(cancel, f) {
    check_args({ promise: { cancel }, function: { f } });
    var listeners = cancel_listener_map.get(cancel);
    if (listeners === 'done') {
        cancel.then(f);
        return;
    }
    if (!listeners) {
        var listeners = new Set();
        cancel_listener_map.set(cancel, listeners);
        cancel.then(a => {
            cancel_listener_map.set(cancel, 'done');
            for (var f of listeners) {
                f(a);
            }
        });
    }
    listeners.add(f);
}

function remove_cancel_listener(cancel, f) {
    var listeners = cancel_listener_map.get(cancel);
    if (listeners instanceof Set) {
        listeners.delete(f);
    }
}

function extend_cancel_promise(cancel) {
    var r, c = new Promise(resolve => r = resolve);
    if (!cancel) return [r, c];
    check_args({ promise: { cancel } });
    add_cancel_listener(cancel, r);
    var trigger = (a) => (r(a), remove_cancel_listener(cancel, r));
    return [trigger, c];
}

class _SocketBase {
    constructor() {
        this._triggers = new Set();
    }

    async callHTTP(method, url, bytes, options, cancel) {
        var { _triggers } = this;
        var [trg, cancel] = extend_cancel_promise(cancel);
        try {
            _triggers.add(trg);
            var res = await callHTTP(method, url, bytes, options, cancel);
        } finally {
            _triggers.delete(trg);
        }
        return res;
    }

    close(error) {
        var { _triggers } = this;
        for (var trg of _triggers) {
            _triggers.delete(trg);
            trg(error);
        }
        if (this.close_handler) this.close_handler(error);
    }
}

class SocketHTTP extends _SocketBase {
    constructor(url, options) {
        super();
        this.url = url;
        this.options = options;
    }

    async call(bytes, spv, cancel) {
        var { url, _triggers } = this;
        if (spv > 0) url += `?spv=${spv}`;
        var res = await super.callHTTP('POST', url, bytes, this.options, cancel);
        return res;
    }

    close(error) {
        super.close(error);
    }
}

class SocketWS extends _SocketBase {
    constructor(url, options) {
        super();
        this.url = url;
        this.options = options;
        this.requests = new Map();
        this.pendings = [];
        this.header = encodeUTF8(JSON.stringify({ version: 3 }));
        this._connect();
    }

    async call(bytes, spv) {
        check_args({ buffer: { bytes } });
        if (!this.ws) {
            this._connect();
        }
        do {
            var key = String(Math.floor(Math.random() * 1000000000));
        } while (this.requests.has(key));
        if (spv > 0) {
            var b = composeUint8Arrays([this.header, bytes, encodeUTF8(key), encodeUTF8(String(spv))]);
        } else {
            var b = composeUint8Arrays([this.header, bytes, encodeUTF8(key)]);
        }
        if (this.ws.readyState === 1) {
            this.ws.send(b);
        } else {
            this.pendings.push(b);
        }
        return new Promise((resolve, reject) => {
            this.requests.set(key, { resolve, reject });
        });
    }

    close(error) {
        var ws = this.ws;
        if (!ws) return;
        this.ws = null;
        try {
            ws.close();
        } catch (err) {}
        this.requests.forEach(({ reject }) => reject(error));
        this.requests.clear();
        this.pendings = [];
        super.close(error);
    }

    _connect() {
        if (typeof window === 'undefined') { // Node.js
            var ws = new(require('ws'))(this.url, this.options);
        } else {
            var ws = new WebSocket(this.url);
        }
        this.ws = ws;
        ws.binaryType = 'arraybuffer';
        ws.onopen = () => {
            if (this.ws !== ws) return;
            try {
                for (var i = 0; i < this.pendings.length; i++) {
                    if (ws.readyState !== 1) break;
                    ws.send(this.pendings[i]);
                }
                this.pendings.splice(0, i);
            } catch (err) {
                this.close(err);
            }
        };
        ws.onerror = ({ message }) => {
            if (this.ws !== ws) return;
            this.close(message || 'socket error');
        };
        ws.onclose = ({ code, reason }) => {
            if (this.ws !== ws) return;
            this.close('socket closed: ' + code + (reason ? ' ' + reason : ''));
        };
        ws.onmessage = ({ data }) => {
            if (this.ws !== ws) return;
            try {
                var [resbin, keybin] = decomposeUint8Arrays(data);
                var key = decodeUTF8(keybin);
                var r = this.requests.get(key);
                if (r == null) {
                    if (this.default_handler) this.default_handler(resbin);
                    return;
                }
                this.requests.delete(key);
                r.resolve(JSON.parse(decodeUTF8(resbin)));
            } catch (err) {
                this.close(err);
            }
        };
    }
}

function createSocket(url, options) {
    check_args({ string: { url } });
    if (url.startsWith("ws://") || url.startsWith("wss://")) {
        return new SocketWS(url, options);
    } else {
        return new SocketHTTP(url, options);
    }
}

'use strict';


function checkCnfProperty(cnf) {
    if (!cnf) throw new Error('null cnf');
    if (typeof cnf !== 'object') throw new Error('cnf not object');
    var { blkno, hash64, N, F, V } = cnf;
    if (!(Number.isSafeInteger(blkno) && blkno > 0)) throw new Error('invalid blkno');
    if (!(typeof hash64 === 'string' && hash64.length <= 100)) throw new Error('invalid hash64');
    var blkhash = decodeBase64(hash64);
    if (blkhash.length !== 32) throw new Error('invalid hash64');
    if (!(Number.isSafeInteger(N) && N > 0)) throw new Error('invalid N');
    if (!(Number.isSafeInteger(F) && F >= 0)) throw new Error('invalid F');
    if (!(Number.isSafeInteger(V) && V >= 0)) throw new Error('invalid V');
}

function checkPeerProperty(peer) {
    if (!peer) throw new Error('null peer');
    if (typeof peer !== 'object') throw new Error('peer not object');
    var { id, authority, pubkey, pubkey2, url } = peer;
    if (!(typeof id === 'string' && id.length <= 50)) throw new Error('invalid id');
    if (!(typeof authority === 'boolean')) throw new Error('invalid authority');
    if (pubkey && !(typeof pubkey === 'string' && pubkey.length <= 1000)) throw new Error('invalid pubkey');
    if (pubkey2 && !(typeof pubkey2 === 'string' && pubkey2.length <= 1000)) throw new Error('invalid pubkey2');
    if (url && !(typeof url === 'string' && url.length <= 8000)) throw new Error('invalid url');
}

async function loadPeersCnf(cnfstr) {
    var pids = [];
    var authorities = [];
    var peers = new Map();
    var pubkeys = new Map();

    try {
        var cnf = JSON.parse(cnfstr);
    } catch (err) {
        throw new Error('invalid cnfstr');
    }
    if (cnfstr !== JSON.stringify(cnf)) throw new Error('unreversible cnfstr');
    checkCnfProperty(cnf);
    if (!Array.isArray(cnf.peers)) throw new Error('invalid peers');
    for (var peer of cnf.peers) {
        checkPeerProperty(peer);
        var pid = peer.id;
        if (peers.has(pid)) throw new Error('duplicated peer');
        peers.set(pid, peer);
        pids.push(pid);
        if (peer.authority) authorities.push(pid);
        var a = [];
        try {
            if (peer.pubkey) a.push(await importPublicKeyFromRsaPem(peer.pubkey));
            if (peer.pubkey2) a.push(await importPublicKeyFromRsaPem(peer.pubkey2));
        } catch (err) {
            throw new Error('unsupported pubkey');
        }
        pubkeys.set(pid, a);
    }
    delete(cnf.peers);

    async function verify(pid, bytes, signature) {
        var a = pubkeys.get(pid);
        for (var pubkey of a) {
            if (await verifySignature(pubkey, bytes, signature)) return true;
        }
        return false;
    }

    return { V: cnf.V, NF: cnf.N - cnf.F, cnfstr, cnf, blkno: cnf.blkno, hash64: cnf.hash64, peers, pids, authorities, verify };
}

async function verifyPeersCnfUpdate(oldcnf, newcnf, signatures) {
    if (!(oldcnf.V < newcnf.V)) throw new Error('invalid version order');
    for (var pid of newcnf.authorities) {
        if (!oldcnf.pids.includes(pid)) throw new Error('unexpected new authority');
    }
    for (var pid of oldcnf.authorities) {
        if (!newcnf.pids.includes(pid)) throw new Error('expected old authority');
    }
    var oldNF = oldcnf.NF;
    var newNF = newcnf.NF;
    var cnfbin = encodeUTF8(oldcnf.cnfstr + newcnf.cnfstr);
    var sigs = new Map();
    try {
        for (var [pid, sig] of signatures) {
            sigs.set(pid, decodeBase64(sig));
        }
    } catch (err) {
        throw new Error('invalid signatures');
    }
    for (var [pid, signature] of sigs) {
        if (!await oldcnf.verify(pid, cnfbin, signature)) continue;
        if (oldcnf.authorities.includes(pid)) oldNF--;
        if (newcnf.authorities.includes(pid)) newNF--;
    }
    if (!(oldNF <= 0 && newNF <= 0)) throw new Error('insufficient signatures');
    return true;
}




/*
abstract RPC interface
    setBFT(B)
    setShowBlockref(b)
    setSPV(peerscnf)
    connect(url, options)
    removeSocket(socket)
    async call(wallet, contract, args, options)
    async fetchBlock(blkno)
    async fetchTxHash(txno)
    async fetchTxHashes(start_txno, end_txno)
    async fetchCnfstr(V)
    async fetchTxSPV(txno)
    async fetchBlockSPV(blkno, V)
    async updatePeersCnf(peerscnf, V)
    close()
*/

class RemoteError extends Error {
    constructor(msg) {
        super(msg);
        this.name = 'RemoteError';
    }
}

class RPC {
    constructor(chainID) {
        if (!chainID) throw new Error('no chainID');
        this.chainID = chainID;
        this.deadline_margin = 100 * 1000; // 100 secs
        this.B = 0;
        this.sockets = new Set();
    }

    setBFT(B) {
        if (!(B === 0 || isPositiveInteger(B))) throw new Error('invalid BFT');
        this.B = B;
    }

    setShowBlockref(b) {
        this.showBlockref = !!b;
    }

    setSPV(peerscnf) {
        this.peerscnf = peerscnf;
    }

    connect(url, options) {
        var socket = createSocket(url, options);
        this.sockets.add(socket);
        return socket;
    }

    removeSocket(socket) {
        this.sockets.delete(socket);
    }

    close(error) {
        for (var socket of this.sockets) {
            socket.close(error || new Error('closed'));
            this.sockets.delete(socket);
        }
    }

    async _multi_call_ex(func, argv, precheck, check, fallback, B) {
        var spvreq = 0;
        if (func == callRequest_ex) var spvreq = argv[1];
        if (!(B === 0 || isPositiveInteger(B))) B = this.B;
        if (!isPositiveInteger(B)) B = 0;
        var remains = this.sockets.size;
        if (!(remains > B)) throw new Error('insufficient connections');
        var [cancel_trigger, cancel] = extend_cancel_promise();
        var ps = [];
        for (var socket of this.sockets) {
            var p = func.apply(null, [cancel, socket, ...argv]);
            ps.push(p);
            p.catch(() => 0);
        }
        if (precheck) await precheck();
        var errors = new Map();
        var counts = new Map();
        return await new Promise((resolve, reject) => {
            for (var p of ps) {
                p.then(resp => {
                        try {
                            if (check) resp = check(resp);
                        } catch (err) {
                            throw 'broken response';
                        }
                        if (resp && func == callRequest_ex) {
                            var spv = resp.spv || 0;
                            delete(resp.spv);
                        }
                        var text = JSON.stringify(resp);
                        var d = counts.get(text);
                        if (!d) {
                            var d = { c: 0, resp, text, spv: 0 };
                            counts.set(text, d);
                        }
                        if (d.spv < spv) d.spv = spv;
                        if (++d.c > B && spvreq <= d.spv) {
                            var resp = JSON.parse(text);
                            if (d.spv) resp.spv = d.spv;
                            remains = Infinity;
                            cancel_trigger('canceled');
                            return resolve(resp);
                        }
                    })
                    .catch(err => {
                        if (typeof err === 'string') {
                            var text = err;
                        } else if (err instanceof Error) {
                            var text = err.message;
                        } else {
                            var text = String(err);
                        }
                        var d = errors.get(text);
                        if (!d) {
                            var d = { c: 0, text };
                            errors.set(text, d);
                        }
                        d.c++;
                    })
                    .then(async () => {
                        if (--remains > 0) return;
                        if (fallback) {
                            try {
                                var resp = await fallback(errors, counts);
                                if (resp) return resolve(resp);
                            } catch (err) {
                                //nothing to do
                            }
                        }
                        var maxd = { c: 0, spv: -1, text: 'insufficient responses' };
                        for (var d of counts.values()) {
                            if (B < d.c && (maxd.spv < d.spv || (maxd.spv === d.spv && maxd.c < d.c))) maxd = d;
                        }
                        if (maxd.c > B) {
                            var resp = JSON.parse(d.text);
                            if (d.spv) resp.spv = d.spv;
                            return resolve(resp);
                        }
                        for (var d of errors.values()) {
                            if (maxd.c < d.c && B < d.c) maxd = d;
                        }
                        return reject(new RemoteError(maxd.text));
                    });
            }
        });
    }

    async call(wallet, contract, args = {}, options = {}) {
        if (!this.blockref) {
            var { blkno, hash64 } = await this.fetchBlock();
            this.blockref = { no: blkno, hash: hash64 };
        }
        options.deadline = Date.now() + (options.deadline_margin || this.deadline_margin);
        options.blockref = this.blockref;
        var spv = this.peerscnf ? 2 : 0;
        if ('spv' in options) {
            var { spv } = options;
            if (!(spv === 0 || spv === 1 || spv === 2)) throw new Error('invalid spv');
        }
        var B = this.B;
        if ('BFT' in options) var B = options.BFT;
        if (!(B === 0 || isPositiveInteger(B))) throw new Error('invalid BFT');
        var request = await createRequest([wallet.address], contract, args, options);
        await signRequest(request, wallet, this.chainID);
        var pack = packRequest(request);
        return this._call_pack(pack, request.reqbin, spv, B);
    }

    async _call_request(request, B) {
        if (!(B === 0 || isPositiveInteger(B))) B = this.B;
        if (!isPositiveInteger(B)) B = 0;
        var spv = this.peerscnf ? 2 : 0;
        var pack = packRequest(request);
        return this._call_pack(pack, request.reqbin, spv, B);
    }

    async _call_pack(pack, reqbin, spv, B) {
        var hash;
        var txidref;
        var resp = await this._multi_call_ex(callRequest_ex, [pack, spv, this.peerscnf],
            // precheck
            (async () => {
                hash = await makeHASH(this.chainID, reqbin);
                txidref = makeTXID(hash);
            }),
            // check
            resp => {
                var { txno, txid, status, value, blockref, spv } = resp;
                if (txno && !isPositiveInteger(txno)) throw 0;
                if (txidref !== txid) throw 0;
                if (typeof status !== 'string') throw 0;
                if (!blockref) return { txno, txid, status, value };
                if (!isPositiveInteger(blockref.no)) throw 0;
                var h = decodeBase64(blockref.hash);
                if (h.length !== 32) throw 0;
                var blockref = { no: blockref.no, hash: blockref.hash };
                if (!spv) return { txno, txid, status, value, blockref };
                if (!isPositiveInteger(spv)) throw 0;
                return { txno, txid, status, value, blockref, spv };
            },
            null, B);
        if (resp.blockref) {
            if (!this.blockref || resp.blockref.no > this.blockref.no) {
                this.blockref = { no: resp.blockref.no, hash: resp.blockref.hash };
            }
            if (!spv && !this.showBlockref) delete(resp.blockref);
        }
        return resp;
    }

    async fetchBlock(blkno = 0) {
        var rpc = this;
        var B = this.B;
        if (!isPositiveInteger(B)) B = 0;
        return rpc._multi_call_ex(fetchBlock_ex, [blkno], null, null, blkno ? null : fallback, B);

        async function fallback(errors, counts) {
            var a = [];
            for (var d of counts.values()) {
                var b = new Array(d.c);
                b.fill(d.resp.blkno);
                a = a.concat(b);
            }
            a.sort((x, y) => (y - x));
            var blkno = a[B];
            if (!isPositiveInteger(blkno)) return;
            return rpc.fetchBlock(blkno);
        }
    }

    async fetchTxHash(txno = 0) {
        var rpc = this;
        var B = this.B;
        if (!isPositiveInteger(B)) B = 0;
        return rpc._multi_call_ex(fetchTxHash_ex, [txno], null, null, txno ? null : fallback, B);

        async function fallback(errors, counts) {
            var a = [];
            for (var d of counts.values()) {
                var b = new Array(d.c);
                b.fill(d.resp.txno);
                a = a.concat(b);
            }
            a.sort((x, y) => (y - x));
            var txno = a[B];
            if (!isPositiveInteger(txno)) return;
            return rpc.fetchTxHash(txno);
        }
    }

    async fetchTxHashes(start_txno, end_txno) {
        return this._multi_call_ex(fetchTxHashes_ex, [start_txno, end_txno]);
    }

    async fetchCnfstr(V = 0) {
        var rpc = this;
        var B = this.B;
        if (!isPositiveInteger(B)) B = 0;
        return rpc._multi_call_ex(fetchCnfstrNoSig_ex, [V], null, null, V ? null : fallback, B);

        async function fallback(errors, counts) {
            var a = [];
            for (var d of counts.values()) {
                var b = new Array(d.c);
                b.fill(d.resp.V);
                a = a.concat(b);
            }
            a.sort((x, y) => (y - x));
            var V = a[B];
            if (!isPositiveInteger(V)) return;
            return rpc.fetchCnfstr(V);
        }
    }

    async fetchTxSPV(txno) {
        return this._multi_call_ex(fetchTxSPV_ex, [txno]);
    }

    async fetchBlockSPV(blkno, V) {
        return this._multi_call_ex(fetchBlockSPV_ex, [blkno, V]);
    }

    async updatePeersCnf(peerscnf, V = 0) {
        if (V === 0) {
            var res = await this.fetchCnfstr(0);
            V = res.V;
        }
        while (peerscnf.V < V) {
            var cnfstr = await this._multi_call_ex(updatePeersCnf1_ex, [peerscnf]);
            var peerscnf = await loadPeersCnf(cnfstr);
        }
        return peerscnf;
    }

}

async function verifySPV1(resp, pack) {
    var { txno, txid, status, value, blockref, spv } = resp;
    if (!spv || !blockref) return false;
    var { reqbin } = unpackRequest(pack);
    var { args, addr } = JSON.parse(decodeUTF8(reqbin));
    if (typeof addr !== 'string') addr = addr[0];
    var { tx: { caller_txno, caller, callee, subtxs, steps, disclosed_to, related_to }, proof } = spv;
    var argstr = JSON.stringify(args);
    var valuestr = JSON.stringify(value);
    var h = await calculateTxHash({ txid, pack, addr, txno, caller_txno, caller, callee, argstr, subtxs, steps, status, valuestr, disclosed_to, related_to });
    for (var p of proof) {
        if (p !== proof[0] && p.indexOf(0) <= 0) throw 'invalid proof format';
        if (p === proof[0] && p.indexOf(0) !== 0) throw 'invalid proof format';
        p = p.map(h => h && decodeBase64(h));
        if (!p.every(h => (h === 0 || h.length === 32))) throw 'invalid proof format';
        p[p.indexOf(0)] = h;
        var h = await sha256.apply(null, p);
    }
    if (encodeBase64(h, true) !== blockref.hash) throw 'not verified';
    return true;
}

async function verifySPV2sigs(resp, peerscnf) {
    var { blockref, spv } = resp;
    if (!spv || !blockref) return false;
    var { rootinfo, sigs, V } = spv;
    if (!(peerscnf && peerscnf.V === V)) return false;
    if (!(sigs && rootinfo)) return false;
    if (!(sigs.length >= peerscnf.NF)) throw 'insufficient sigs';
    rootinfo[1] = blockref.no;
    rootinfo[4] = blockref.hash;
    var stream = [];
    var arr = [null];
    stream.push(2);
    stream.push(7);
    for (var i = 0; i < rootinfo.length; i++) {
        var a = rootinfo[i];
        stream.push(String(i));
        if (typeof a === 'number') {
            stream.push(7);
            stream.push(a);
        } else {
            stream.push(17);
            stream.push(-arr.length);
            arr.push(decodeBase64(a));
        }
    }
    stream.push(0);
    arr[0] = encodeUTF8(JSON.stringify(stream));
    var bin = composeUint8Arrays(arr);
    for (var [origin, signature] of sigs) {
        if (!await peerscnf.verify(origin, bin, decodeBase64(signature))) throw 'not verified';
    }
    return true;
}

async function verifySPV2chain(resp, peerscnf) {
    var { blockref, spv } = resp;
    if (!spv || !blockref) return false;
    var { blkinfo, blkproof } = spv;
    if (!(blkinfo && blkproof)) return false;
    blkinfo[0] = blockref.no;
    var h = await sha256(encodeUTF8(JSON.stringify(blkinfo) + ';'));
    var p = blkproof[0];
    if (p.indexOf(0) !== 0) throw 'invalid proof format';
    p = p.map(h => h && decodeBase64(h));
    if (!p.every(h => (h === 0 || h.length === 32))) throw 'invalid proof format';
    p[0] = h;
    var h = await sha256.apply(null, p);
    if (encodeBase64(h, true) !== blockref.hash) throw 'not verified';
    for (var p of blkproof.slice(1)) {
        if (p.indexOf(0) <= 0) throw 'invalid proof format';
        p = p.map(h => h && decodeBase64(h));
        if (!p.every(h => (h === 0 || h.length === 32))) throw 'invalid proof format';
        p[p.indexOf(0)] = h;
        var h = await sha256.apply(null, p);
    }
    if (encodeBase64(h, true) !== peerscnf.hash64) throw 'not verified';
    return true;
}

function verifySPV(socket, pack, resp, spvreq, peerscnf) {
    return verifySPV_ex(null, socket, pack, resp, spvreq, peerscnf);
}

async function verifySPV_ex(cancel, socket, pack, resp, spvreq, peerscnf) {
    var { txno, blockref, spv } = resp;
    assert(blockref);
    if (!spvreq || !spv || !spv.tx) return 0;
    if (!spv.proof) {
        var res = await fetchTxSPV_ex(cancel, socket, txno);
        if (!res || !res.proof) return 0;
        spv.proof = res.proof;
    }
    if (!await verifySPV1(resp, pack)) return 0;
    if (spvreq <= 1 || !peerscnf) return 1;
    if (!spv.sigs && !spv.blkinfo) {
        var res = await fetchBlockSPV_ex(cancel, socket, blockref.no, peerscnf.V);
        spv.V = res.V;
        spv.rootinfo = res.rootinfo;
        spv.sigs = res.sigs;
        spv.blkinfo = res.blkinfo;
        spv.blkproof = res.blkproof;
    }
    if (spv.V) {
        peerscnf = await updatePeersCnf_ex(cancel, socket, peerscnf, spv.V);
    }
    if (await verifySPV2sigs(resp, peerscnf)) return 2;
    if (await verifySPV2chain(resp, peerscnf)) return 2;
    return 1;
}

function callRequest(socket, pack, spvreq, peerscnf) {
    return callRequest_ex(null, socket, pack, spvreq, peerscnf);
}

async function callRequest_ex(cancel, socket, pack, spvreq, peerscnf) {
    if (!isPositiveInteger(spvreq)) spvreq = 0;
    var resp = await socket.call(pack, spvreq, cancel);
    if (resp.error) {
        throw new RemoteError(resp.error);
    }
    var { txno, txid, status, value, blockref, spv } = resp;
    if (!blockref) {
        return { txno, txid, status, value };
    }
    try {
        var spv = await verifySPV_ex(cancel, socket, pack, resp, spvreq, peerscnf);
        if (!spv) return { txno, txid, status, value, blockref };
        return { txno, txid, status, value, blockref, spv };
    } catch (err) {
        if (typeof err === 'string') throw new Error('SPV failed: ' + err);
        throw new Error('SPV failed');
    }
}

function convert_url(socket) {
    if (typeof socket === 'string') {
        var url = socket;
        var socket = createSocket(url);
    } else {
        var url = socket.url;
        var options = socket.options;
    }
    var m = /^([^:]+):\/\/([^/]+)/.exec(url);
    if (!m) throw new Error('invalid URL');
    var proto = m[1].replace('ws', 'http');
    var host = m[2];
    return { socket, proto, host, options };
}

function fetchBlock(socket, blkno) {
    return fetchBlock_ex(null, socket, blkno);
}

async function fetchBlock_ex(cancel, socket, blkno = 0) {
    if (!(Number.isInteger(blkno) && 0 <= blkno)) throw new Error('invalid blkno');
    var { socket, proto, host, options } = convert_url(socket);
    var resp = await socket.callHTTP('GET', `${proto}://${host}/block/${blkno}`, undefined, options, cancel);
    try {
        return checkBlockResp(resp, blkno);
    } catch (err) {
        throw 'invalid response';
    }
}

function checkBlockResp(resp, refblkno) {
    var { blkno, time, seed, records, status, hash64, start_txno, end_txno } = resp;
    if (!isPositiveInteger(blkno)) throw 0;
    if (refblkno && refblkno !== blkno) throw 0;
    if (!isPositiveInteger(time)) throw 0;
    if (typeof seed !== 'string') throw 0;
    if (!isPositiveInteger(records)) throw 0;
    if (typeof status !== 'string') throw 0;
    var h = decodeBase64(hash64);
    if (h.length !== 32) throw 0;
    if (!isPositiveInteger(start_txno)) throw 0;
    if (!isPositiveInteger(end_txno)) throw 0;
    if (!(start_txno <= end_txno)) throw 0;
    return { blkno, time, seed, records, status, hash64, start_txno, end_txno };
}

function fetchTxHash(socket, txno) {
    return fetchTxHash_ex(null, socket, txno);
}

async function fetchTxHash_ex(cancel, socket, txno = 0) {
    if (!(Number.isInteger(txno) && 0 <= txno)) throw new Error('invalid txno');
    var { socket, proto, host, options } = convert_url(socket);
    var resp = await socket.callHTTP('GET', `${proto}://${host}/txhash/${txno}`, undefined, options, cancel);
    try {
        return checkTxResp(resp, txno);
    } catch (err) {
        throw 'invalid response';
    }
}

function checkTxResp(resp, reftxno) {
    var { txno, txid, status, hash64 } = resp;
    if (!isPositiveInteger(txno)) throw 0;
    if (reftxno && reftxno !== txno) throw 0;
    if (txid && !isValidTXIDFormat(txid)) throw 0;
    if (typeof status !== 'string') throw 0;
    var h = decodeBase64(hash64);
    if (h.length !== 32) throw 0;
    return { txno, txid, status, hash64 };
}

function fetchTxHashes(socket, start_txno, end_txno) {
    return fetchTxHashes_ex(null, socket, start_txno, end_txno);
}

async function fetchTxHashes_ex(cancel, socket, start_txno, end_txno) {
    if (!(Number.isInteger(start_txno) && 0 < start_txno)) throw new Error('invalid start_txno');
    if (!(Number.isInteger(end_txno) && 0 < end_txno)) throw new Error('invalid end_txno');
    if (start_txno > end_txno) throw new Error('invalid range');
    var { socket, proto, host, options } = convert_url(socket);
    var resp = await socket.callHTTP('GET', `${proto}://${host}/txhashes/${start_txno}-${end_txno}`, undefined, options, cancel);
    try {
        if (!Array.isArray(resp)) throw 0;
        return resp.map(e => {
            if (!(start_txno <= e.txno && e.txno <= end_txno)) throw 0;
            return checkTxResp(e);
        });
    } catch (err) {
        throw 'invalid response';
    }
}

function fetchCnfstr(socket, V) {
    return fetchCnfstr_ex(null, socket, V);
}

async function fetchCnfstrNoSig_ex(cancel, socket, V) {
    var resp = await fetchCnfstr_ex(cancel, socket, V);
    var { V, cnfstr, signatures } = resp;
    return { V, cnfstr };
}

async function fetchCnfstr_ex(cancel, socket, V = 0) {
    if (!(Number.isInteger(V) && 0 <= V)) throw new Error('invalid V');
    var { socket, proto, host, options } = convert_url(socket);
    var resp = await socket.callHTTP('GET', `${proto}://${host}/cnfstr/${V}`, undefined, options, cancel);
    try {
        return checkCnfstrResp(resp, V);
    } catch (err) {
        throw 'invalid response';
    }
}

function checkCnfstrResp(resp, refV) {
    var { V, cnfstr, signatures } = resp;
    if (!isPositiveInteger(V)) throw 0;
    if (refV == 0) return { V };
    if (typeof cnfstr !== 'string') throw 0;
    JSON.parse(cnfstr);
    signatures = JSON.parse(signatures);
    if (!Array.isArray(signatures)) throw 0;
    if (!signatures.every(Array.isArray)) throw 0;
    for (var [pid, sig] of signatures) {
        if (typeof pid !== 'string') throw 0;
        if (typeof sig !== 'string') throw 0;
        decodeBase64(sig);
    }
    return { V, cnfstr, signatures };
}

function fetchTxSPV(socket, txno) {
    return fetchTxSPV_ex(null, socket, txno);
}

async function fetchTxSPV_ex(cancel, socket, txno) {
    if (!(Number.isInteger(txno) && 0 < txno)) throw new Error('invalid txno');
    var { socket, proto, host, options } = convert_url(socket);
    var resp = await socket.callHTTP('GET', `${proto}://${host}/txspv/${txno}`, undefined, options, cancel);
    try {
        return checkTxSPV(resp, txno);
    } catch (err) {
        throw 'invalid response';
    }
}

function checkTxSPV(resp, txno) {
    var { proof, blockref } = resp;
    if (!Array.isArray(proof)) throw 0;
    if (!proof.every(e => Array.isArray(e) && e.every(s => s === 0 || typeof s === 'string'))) throw 0;
    if (!isPositiveInteger(blockref.no)) throw 0;
    var h = decodeBase64(blockref.hash);
    if (h.length !== 32) throw 0;
    return { proof, blockref: { no: blockref.no, hash: blockref.hash } };
}

function fetchBlockSPV(socket, blkno, V) {
    return fetchBlockSPV_ex(null, socket, blkno, V);
}

async function fetchBlockSPV_ex(cancel, socket, blkno, V) {
    if (!(Number.isInteger(blkno) && 0 < blkno)) throw new Error('invalid blkno');
    if (!(Number.isInteger(V) && 0 < V)) throw new Error('invalid V');
    var { socket, proto, host, options } = convert_url(socket);
    var resp = await socket.callHTTP('GET', `${proto}://${host}/blockspv/${blkno}/${V}`, undefined, options, cancel);
    try {
        return checkBlockSPV(resp);
    } catch (err) {
        throw 'invalid response';
    }
}

function checkBlockSPV(resp) {
    var { V, rootinfo, sigs, blkinfo, blkproof } = resp;
    if (!isPositiveInteger(V)) throw 0;
    if (rootinfo || sigs) {
        if (!Array.isArray(rootinfo)) throw 0;
        if (!rootinfo.every(e => ['number', 'string'].includes(typeof e))) throw 0;
        if (!Array.isArray(sigs)) throw 0;
        if (!sigs.every(e => Array.isArray(e) && e.length === 2 && e.every(s => typeof s === 'string'))) throw 0;
    }
    if (blkinfo || blkproof) {
        if (!Array.isArray(blkinfo)) throw 0;
        if (!blkinfo.every(e => ['number', 'string'].includes(typeof e))) throw 0;
        if (!Array.isArray(blkproof)) throw 0;
        if (!blkproof.every(e => Array.isArray(e) && e.every(s => s === 0 || typeof s === 'string'))) throw 0;
    }
    return { V, rootinfo, sigs, blkinfo, blkproof };
}

function updatePeersCnf(socket, peerscnf, V) {
    return updatePeersCnf_ex(null, socket, peerscnf, V);
}

async function updatePeersCnf1_ex(cancel, socket, peerscnf) {
    var peerscnf = await updatePeersCnf_ex(cancel, socket, peerscnf, peerscnf.V + 1);
    return peerscnf.cnfstr;
}

async function updatePeersCnf_ex(cancel, socket, peerscnf, V = 0) {
    if (V === 0) {
        var res = await fetchCnfstr_ex(cancel, socket, 0);
        V = res.V;
    }
    while (peerscnf.V < V) {
        var res = await fetchCnfstr_ex(cancel, socket, peerscnf.V + 1);
        var { cnfstr, signatures } = res;
        var newcnf = await loadPeersCnf(cnfstr);
        await verifyPeersCnfUpdate(peerscnf, newcnf, signatures);
        peerscnf = newcnf;
    }
    return peerscnf;
}

function postAttachment(socket, txno, bytes) {
    return postAttachment_ex(null, socket, txno, bytes);
}

async function postAttachment_ex(cancel, socket, txno, bytes) {
    check_args({ length: { txno }, buffer: { bytes } });
    var { socket, proto, host, options } = convert_url(socket);
    return socket.callHTTP('POST', `${proto}://${host}/attachment/${txno}`, bytes, options, cancel);
}

function getAttachment(socket, txno, hash, wallet, chainID) {
    return getAttachment_ex(null, socket, txno, hash, wallet, chainID);
}

async function getAttachment_ex(cancel, socket, txno, hash, wallet, chainID) {
    check_args({ length: { txno }, string: { hash, chainID } });
    try {
        decodeBase64(hash);
    } catch (err) {
        throw new Error('invalid hash encoding');
    }
    var { socket, proto, host, options } = convert_url(socket);
    var request = await createRequest([wallet.address], 'c1query', { type: 'attachment', txno, hash });
    await signRequest(request, wallet, chainID);
    options = Object.assign({}, options);
    options.rawResponse = true;
    return socket.callHTTP('POST', `${proto}://${host}/get-attachment`, packRequest(request), options, cancel);
}

function callStorage(socket, request, data) {
    return callStorage_ex(null, socket, request, data);
}

async function callStorage_ex(cancel, socket, request, data) {
    var { socket, proto, host, options } = convert_url(socket);
    options = Object.assign({}, options);
    options.rawResponse = true;
    if (data) {
        var bin = composeUint8Arrays([packRequest(request), data]);
    } else {
        var bin = composeUint8Arrays([packRequest(request)]);
    }
    var res = await socket.callHTTP('POST', `${proto}://${host}/storage`, bin, options, cancel);
    try {
        var arr = decomposeUint8Arrays(res);
        var resp = JSON.parse(decodeUTF8(arr[0]));
    } catch (err) {
        throw new Error('invalid response');
    }
    if (arr[1] && resp) {
        resp.data = arr[1];
    }
    return resp;
}



const syncwait_default = 10000;

var gf256_expf = [];
var gf256_logf = [];
var x = 1;
for (var i = 0; i < 255; i++) {
    gf256_expf[i] = x;
    gf256_logf[x] = i;
    x <<= 1;
    if (x & 256) x ^= 285;
}
assert(x === 1);

function sssDistribute(data, N, T, ys) {
    check_args({ uint8array: { data }, length: { N, T } });
    if (!(1 <= N && N <= 255)) throw new Error(`argument "N" out of bounds`);
    if (!(1 <= T && T <= N)) throw new Error(`argument "T" out of bounds`);
    var len = data.length;
    if (!ys) {
        var ys = [];
        for (var i = 0; i < N; i++) {
            ys[i] = new Uint8Array(len);
        }
    } else {
        check_args({ array: { ys } });
        if (ys.length !== N) throw new Error(`ys.length !== N`);
        for (var i = 0; i < N; i++) {
            if (!(ys[i] instanceof Uint8Array)) throw new Error(`argument "ys[${i}]" is not an instance of Uint8Array`);
        }
    }
    var c = [];
    for (var j = 1; j < T; j++) {
        c[j] = makeRandomUint8Array(len);
    }
    for (var k = 0; k < len; k++) {
        for (var i = 0; i < N; i++) {
            var a = data[k];
            var e = gf256_logf[i + 1];
            for (var j = 1; j < T; j++) {
                var u = c[j][k];
                if (u === 0) continue;
                a ^= gf256_expf[(gf256_logf[u] + e * j) % 255];
            }
            ys[i][k] = a;
        }
    }
    return ys;
}

function sssRevert(ys, N, T) {
    check_args({ array: { ys }, length: { N, T } });
    if (!(1 <= N && N <= 255)) throw new Error(`argument "N" out of bounds`);
    if (!(1 <= T && T <= N)) throw new Error(`argument "T" out of bounds`);
    if (ys.length !== N) throw new Error(`ys.length !== N`);
    var x = [];
    var y = [];
    for (var i = 0; i < ys.length; i++) {
        if (ys[i] == null) continue;
        if (!(ys[i] instanceof Uint8Array)) throw new Error(`argument "ys[${i}]" is not an instance of Uint8Array`);
        x.push(i + 1);
        y.push(ys[i]);
    }
    if (y.length !== T) throw new Error(`the number of shares !== T`);
    var z = [...new Set(y.map(a => a.length))];
    if (z.length !== 1) throw new Error(`lengths of shares are not same`);
    var len = z[0];
    var v = [];
    for (var j = 0; j < T; j++) {
        var a = 0;
        for (var m = 0; m < T; m++) {
            if (j === m) continue;
            a += gf256_logf[x[m]] - gf256_logf[x[m] ^ x[j]] + 255;
        }
        v[j] = a % 255;
    }
    var data = new Uint8Array(len);
    for (var k = 0; k < len; k++) {
        var a = 0;
        for (var j = 0; j < T; j++) {
            var u = y[j][k];
            if (u === 0) continue;
            a ^= gf256_expf[(gf256_logf[u] + v[j]) % 255];
        }
        data[k] = a;
    }
    return data;
}

function Overlap(m) {
    var max = m;
    var para = 0;
    var kick;
    var waitp;
    Object.assign(this, { setMax, wait, inc, dec });

    function update() {
        if (para < max && kick) {
            kick();
            kick = null;
        }
        if (para >= max && !kick) {
            waitp = new Promise(r => kick = r);
        }
    }

    async function wait() {
        while (para >= max) {
            await waitp;
        }
    }

    function inc() {
        para++;
        update();
    }

    function dec() {
        para--;
        assert(para >= 0);
        update();
    }

    function setMax(m) {
        max = m;
        update();
    }
}

async function wait_interval(ctx) {
    var { interval, syncwait, cancel } = ctx;
    if (syncwait <= 0) return false;
    var [cancel_trigger, cancel] = extend_cancel_promise(cancel);
    var tid = setTimeout(() => (tid = null, cancel_trigger(ctx)), Math.min(interval, syncwait));
    try {
        var e = await cancel;
        if (ctx !== e) throw e;
    } finally {
        if (tid != null) clearTimeout(tid);
    }
    ctx.syncwait -= interval;
    ctx.interval = Math.min(interval * 2, 10000);
    return true;
}

async function sssParamPeer(sss, { uw, cid, key, syncwait }, pid, cancel) {
    var { chainID, pid_sockets, excluded_pids } = sss;
    if (excluded_pids.has(pid)) throw 'excluded';
    var socket = pid_sockets.get(pid);
    var ctx = { interval: 100, syncwait, cancel };
    while (true) {
        var request = await createRequest(uw.address, cid, { cmd: 'param', key, peer: pid });
        await signRequest(request, uw, chainID);
        var resp = await callStorage_ex(cancel, socket, request);
        if (!(resp && typeof resp.status === 'string')) throw new Error('invalid response'); // just in case
        if (resp.status === 'not found' && await wait_interval(ctx)) continue;
        if (resp.status !== 'ok') throw resp.status;
        return resp.value;
    }
}

async function sssWriteChunkPeer(sss, { uw, cid, key, chunk, ver, syncwait }, pid, data, cancel) {
    var { chainID, pid_sockets, excluded_pids } = sss;
    if (excluded_pids.has(pid)) return;
    var socket = pid_sockets.get(pid);
    var hash = encodeBase64(await sha256(data));
    var ctx = { interval: 100, syncwait, cancel };
    while (true) {
        var request = await createRequest(uw.address, cid, { cmd: 'write', key, chunk, hash, peer: pid, ver });
        await signRequest(request, uw, chainID);
        var resp = await callStorage_ex(cancel, socket, request, data);
        if (!(resp && typeof resp.status === 'string')) throw new Error('invalid response'); // just in case
        if (resp.status === 'not found' && await wait_interval(ctx)) continue;
        if (resp.status !== 'ok') throw resp.status;
        return;
    }
}

async function sssReadChunkPeer(sss, { uw, cid, key, chunk, ver, syncwait }, pid, cancel) {
    var { chainID, pid_sockets, excluded_pids } = sss;
    if (excluded_pids.has(pid)) throw 'excluded';
    var socket = pid_sockets.get(pid);
    if (!socket) throw 'unknown pid';
    var ctx = { interval: 100, syncwait, cancel };
    while (true) {
        var request = await createRequest(uw.address, cid, { cmd: 'read', key, chunk, peer: pid, ver });
        await signRequest(request, uw, chainID);
        var resp = await callStorage_ex(cancel, socket, request);
        if (!(resp && typeof resp.status === 'string')) throw new Error('invalid response'); // just in case
        if (resp.status === 'not found' && await wait_interval(ctx)) continue;
        if (resp.status !== 'ok') throw resp.status;
        if (!(resp.data instanceof Uint8Array)) throw new Error('invalid response'); // just in case
        return resp.data;
    }
}

function makeMultipleError(msg, errors) {
    var err = new Error(msg);
    var ms = new Set();
    for (var [pid, err] of errors) {
        if (err instanceof Error) {
            var m = err.message;
        } else if (typeof err === 'string') {
            var m = err;
        }
        if (typeof m !== 'string') {
            var m = String(m) || '';
        }
        ms.add(m);
        if (err1 == null) {
            if (err instanceof Error) {
                var err1 = err;
            } else {
                var err1 = new Error(m);
            }
        }
    }
    if (ms.size === 1 || (ms.size === 2 && [...ms][1] === 'canceled')) {
        var err = err1;
    } else {
        var err = new Error(msg);
    }
    err.details = [...errors];
    return err;
}

async function sssParam(sss, dir, cancel) {
    var { pids, overlap_call: overlap } = sss;
    var [cancel_trigger, cancel] = extend_cancel_promise(cancel);
    var errors = new Map();
    var counts = new Map();
    var ps = [];
    for (let pid of pids) {
        await overlap.wait();
        overlap.inc();
        ps.push(sssParamPeer(sss, dir, pid, cancel)
            .then(value => {
                var k = JSON.stringify(value);
                var c = counts.get(k);
                if (!c) {
                    var c = [];
                    counts.set(k, c);
                }
                c.push(pid);
            })
            .catch(err => {
                if (err === 'excluded') return;
                errors.set(pid, err);
                cancel_trigger('canceled');
            })
            .then(() => {
                overlap.dec();
            }));
    }
    await Promise.all(ps);
    if (errors.size > 0) {
        throw makeMultipleError('multiple errors', errors);
    }
    if (counts.size === 0) throw new Error('no data');
    if (counts.size > 1) {
        var err = new Error('inconsistent');
        var errors = [];
        for (var [k, c] of counts) {
            errors.push([c, JSON.parse(k)]);
        }
        err.details = [...errors];
        throw err;
    }
    return JSON.parse(counts.keys().next().value);
}

async function sssWriteChunk(sss, dir, bytes, cancel) {
    var { T, pids, overlap_call: overlap } = sss;
    var N = pids.length;
    var hsize = 32 * N;
    var size = hsize + bytes.length + 32;
    var bs = [];
    var ys = [];
    for (var i = 0; i < N; i++) {
        bs[i] = new Uint8Array(size);
        ys[i] = bs[i].subarray(hsize, size - 32);
    }
    sssDistribute(bytes, N, T, ys);
    var hashes = [];
    for (var i = 0; i < N; i++) {
        bs[i].set(makeRandomUint8Array(32), size - 32);
        hashes[i] = await sha256(bs[i].subarray(hsize, size));
    }
    var header = concatUint8Arrays(hashes);
    for (var i = 0; i < N; i++) {
        bs[i].set(header, 0);
    }
    var [cancel_trigger, cancel] = extend_cancel_promise(cancel);
    var errors = new Map();
    var ps = [];
    for (let i = 0; i < N; i++) {
        await overlap.wait();
        if (errors.size > 0) break;
        overlap.inc();
        ps[i] = sssWriteChunkPeer(sss, dir, pids[i], bs[i], cancel)
            .catch(err => {
                errors.set(pids[i], err);
                cancel_trigger('canceled');
            })
            .then(() => {
                overlap.dec();
            });
    }
    await Promise.all(ps);
    if (errors.size > 0) {
        throw makeMultipleError('multiple errors', errors);
    }
}

async function sssReadChunk(sss, pids, dir, cancel) {
    var { T, overlap_call: overlap } = sss;
    var N = pids.length;
    var { len } = dir;
    var hsize = 32 * pids.length;
    var [cancel_trigger, cancel] = extend_cancel_promise(cancel);
    var errors = new Map();
    var counts = new Map();
    var remains = pids.length;
    var max_collected = 0;
    var collected;
    var ps = [];
    for (let i = 0; i < N; i++) {
        let pid = pids[i];
        await overlap.wait();
        if (collected || max_collected + remains < T) break;
        overlap.inc();
        ps.push(sssReadChunkPeer(sss, dir, pid, cancel)
            .then(async data => {
                if (len > 0) {
                    var size = hsize + len + 32;
                    if (data.length !== size) throw new Error('unexpected size of chunk data');
                } else {
                    var size = data.length;
                    if (hsize + 32 > size) throw new Error('unexpected size of chunk data');
                }
                var hash = await sha256(data.subarray(hsize, size));
                var hashref = data.subarray(i * 32, (i + 1) * 32);
                if (encodeBase64(hash) !== encodeBase64(hashref)) throw new Error('unexpected hash');
                if (collected) throw 'canceled';
                var k = encodeBase64(data.subarray(0, hsize));
                if (!(len > 0)) k += '#' + size;
                var y = data.subarray(hsize, size - 32);
                var c = counts.get(k);
                if (!c) {
                    var c = [];
                    counts.set(k, c);
                }
                c.push([i, y]);
                max_collected = Math.max(max_collected, c.length);
                if (c.length === T) {
                    collected = c;
                    cancel_trigger('canceled');
                }
            })
            .catch(err => {
                errors.set(pid, err);
            })
            .then(() => {
                overlap.dec();
                remains--;
                if (max_collected + remains < T) {
                    cancel_trigger('canceled');
                }
            }));
    }
    await Promise.all(ps);
    if (!collected) {
        throw makeMultipleError('insufficient valid responses', errors);
    }
    var ys = new Array(N);
    collected.forEach(([i, y]) => (ys[i] = y));
    return sssRevert(ys, N, T);
}

async function sssWriteFileHeader(sss, dir, header, cancel) {
    var { pids, overlap_call: overlap } = sss;
    var bytes = encodeUTF8(JSON.stringify(header));
    var [cancel_trigger, cancel] = extend_cancel_promise(cancel);
    var errors = new Map();
    var ps = [];
    for (let pid of pids) {
        await overlap.wait();
        if (errors.size > 0) break;
        overlap.inc();
        ps.push(sssWriteChunkPeer(sss, dir, pid, bytes, cancel)
            .catch(err => {
                errors.set(pid, err);
                cancel_trigger('canceled');
            })
            .then(() => {
                overlap.dec();
            }));
    }
    await Promise.all(ps);
    if (errors.size > 0) {
        throw makeMultipleError('multiple errors', errors);
    }
}

function checkValidHeader(data, cond) {
    try {
        var { T, pids, ver, ysize, length } = JSON.parse(decodeUTF8(data));
    } catch (err) {
        throw 'invalid format';
    }
    if (!(Array.isArray(pids) && pids.every(pid => (getTypeofId(pid) === 'peer')))) throw 'invalid pids';
    var N = pids.length;
    if (!(1 <= N && N <= 255)) throw 'invalid N';
    if (!(Number.isSafeInteger(T) && 1 <= T && T <= N)) throw 'invalid T';
    if (ver !== undefined && !(Number.isSafeInteger(ver) && ver > 0)) throw 'invalid ver';
    if (!(Number.isSafeInteger(ysize) && ysize > 0)) throw 'invalid ysize';
    if (!(Number.isSafeInteger(length) && length >= 0)) throw 'invalid length';
    if (cond.ver && ver !== cond.ver) throw `unexpected ver: ${ver}`;
    if (T !== cond.T) throw `unexpected T: ${T}`;
    var set = new Set(pids);
    var c = 0;
    for (var pid of cond.pids) {
        if (set.has(pid)) {
            c++;
            set.delete(pid);
        }
    }
    if (c < T) throw `insufficient pids: ${[...set].join()}`;
    return { T, pids, ver, ysize, length };
}

async function sssReadFileHeader(sss, dir, cancel) {
    var { T, pids, overlap_call: overlap } = sss;
    var { ver } = dir;
    var [cancel_trigger, cancel] = extend_cancel_promise(cancel);
    var errors = new Map();
    var counts = new Map();
    var remains = pids.length;
    var max_collected = 0;
    var collected;
    var ps = [];
    for (let pid of pids) {
        await overlap.wait();
        if (collected || max_collected + remains < T) break;
        overlap.inc();
        ps.push(sssReadChunkPeer(sss, dir, pid, cancel)
            .then(async data => {
                var header = checkValidHeader(data, { ver, T, pids });
                var k = encodeBase64(data);
                var c = counts.get(k);
                if (!c) {
                    var c = { header, pids: [] };
                    counts.set(k, c);
                }
                c.pids.push(pid);
                max_collected = Math.max(max_collected, c.length);
                if (c.pids.length === T) {
                    collected = c;
                    cancel_trigger('canceled');
                }
            })
            .catch(err => {
                errors.set(pid, err);
            })
            .then(() => {
                overlap.dec();
                remains--;
                if (max_collected + remains < T) {
                    cancel_trigger('canceled');
                }
            }));
    }
    await Promise.all(ps);
    if (!collected) {
        throw makeMultipleError('insufficient valid headers', errors);
    }
    return collected;
}

async function sssWriteFile(sss, dir, file, cancel) {
    var { T, pids, overlap_chunk: overlap } = sss;
    var N = pids.length;
    var { ver } = dir;
    var [cancel_trigger, cancel] = extend_cancel_promise(cancel);
    var params = await sssParam(sss, dir, cancel);
    var { chunksize, chunks } = params;
    var ysize = chunksize - 32 * N - 32;
    if (ysize < 1) throw new Error('too small chunksize');
    var length = file.length;
    if (ysize * (chunks - 1) < length) throw new Error('too large file');
    var header = { T, pids, ver, ysize, length };
    await sssWriteFileHeader(sss, { ...dir, chunk: 0 }, header, cancel);
    var pendings = new Set();
    var errors = [];
    for (let chunk = 0; chunk * ysize < length; chunk++) {
        await overlap.wait();
        if (errors.length > 0) break;
        overlap.inc();
        var bytes = file.subarray(chunk * ysize, (chunk + 1) * ysize);
        let p = sssWriteChunk(sss, { ...dir, chunk: chunk + 1 }, bytes, cancel)
            .catch(err => {
                err.chunk = chunk + 1;
                errors.push(err);
                cancel_trigger('canceled');
            })
            .then(() => {
                overlap.dec();
                pendings.delete(p);
            });
        pendings.add(p);
    }
    await Promise.all([...pendings]);
    if (errors.length > 0) {
        throw errors[0];
    }
}

async function sssReadFile(sss, dir, cancel) {
    var { overlap_chunk: overlap } = sss;
    var [cancel_trigger, cancel] = extend_cancel_promise(cancel);
    var { header } = await sssReadFileHeader(sss, { ...dir, chunk: 0 }, cancel);
    var { pids, ver, ysize, length } = header;
    var file = new Uint8Array(length);
    var pendings = new Set();
    var errors = [];
    for (let chunk = 0; chunk * ysize < length; chunk++) {
        await overlap.wait();
        if (errors.length > 0) break;
        overlap.inc();
        let p = sssReadChunk(sss, pids, { ...dir, ver, chunk: chunk + 1, len: Math.min(ysize, length - chunk * ysize) }, cancel)
            .then(data => {
                file.set(data, chunk * ysize);
            })
            .catch(err => {
                err.chunk = chunk + 1;
                errors.push(err);
                cancel_trigger('canceled');
            })
            .then(() => {
                overlap.dec();
                pendings.delete(p);
            });
        pendings.add(p);
    }
    await Promise.all([...pendings]);
    if (errors.length > 0) {
        throw errors[0];
    }
    return file;
}

async function call_with_timeout(func, args, { timeout, cancel }) {
    if (timeout != null) {
        var [cancel_trigger, cancel] = extend_cancel_promise(cancel);
        var tid = setTimeout(() => (tid = null, cancel_trigger('timeout')), timeout);
    }
    try {
        return await func.apply(null, [...args, cancel]);
    } finally {
        if (tid != null) clearTimeout(tid);
    }
}

class StorageSSS {
    constructor(chainID, N, T, pid_sockets) {
        // N: not used
        check_args({ string: { chainID }, length: { T }, array: { pid_sockets } });
        this.chainID = chainID;
        this.T = T;
        for (var i = 0; i < pid_sockets.length; i++) {
            if (!Array.isArray(pid_sockets[i])) throw new Error(`pid_sockets[${i}] is not an array`);
            if (2 !== pid_sockets[i].length) throw new Error(`pid_sockets[${i}].length !== 2`);
        }
        for (var i = 0; i < pid_sockets.length; i++) {
            var [pid, socket] = pid_sockets[i];
            if (getTypeofId(pid) !== 'peer') throw new Error(`invalid pid: pid_sockets[${i}]`);
            try {
                var { socket } = convert_url(socket);
            } catch (err) {
                throw new Error(`invalid socket: pid_sockets[${i}]: ${err.message}`);
            }
        }
        var m = new Map(pid_sockets);
        if (m.size !== pid_sockets.length) throw new Error('duplicate pids');
        this.pid_sockets = m;
        this.pids = [...m.keys()];
        this.setExclude();
        this.overlap_chunk = new Overlap(4);
        this.overlap_call = new Overlap(4 * m.size);
    }

    setConcurrency(p, q) {
        if (!q) q = p * this.pid_sockets.size;
        check_args({ length: { p, q } });
        this.overlap_chunk.setMax(p);
        this.overlap_call.setMax(q);
    }

    setExclude(pid) {
        check_args({ string: arguments });
        this.excluded_pids = new Set(arguments);
    }

    async param(uw, cid, { key, syncwait = syncwait_default }, { timeout, cancel } = {}) {
        check_args({ object: { uw }, string: { cid, key }, length_opt: { syncwait, timeout }, promise_opt: { cancel } });
        return call_with_timeout(sssParam, [this, { uw, cid, key, syncwait }], { timeout, cancel });
    }

    async writeChunk(uw, cid, { key, chunk, ver, syncwait = syncwait_default }, bytes, { timeout, cancel } = {}) {
        check_args({ object: { uw }, string: { cid, key }, length: { chunk }, length_opt: { ver, syncwait, timeout }, uint8array: { bytes }, promise_opt: { cancel } });
        ver = ver || undefined;
        return call_with_timeout(sssWriteChunk, [this, { uw, cid, key, chunk, ver, syncwait }, bytes], { timeout, cancel });
    }

    async readChunk(uw, cid, { key, chunk, ver, syncwait = syncwait_default }, { timeout, cancel } = {}) {
        check_args({ object: { uw }, string: { cid, key }, length: { chunk }, length_opt: { ver, syncwait, timeout }, promise_opt: { cancel } });
        ver = ver || undefined;
        return call_with_timeout(sssReadChunk, [this, this.pids, { uw, cid, key, chunk, ver, syncwait }], { timeout, cancel });
    }

    async writeFile(uw, cid, { key, ver, syncwait = syncwait_default }, bytes, { timeout, cancel } = {}) {
        check_args({ object: { uw }, string: { cid, key }, uint8array: { bytes }, length_opt: { ver, syncwait, timeout }, promise_opt: { cancel } });
        ver = ver || undefined;
        return call_with_timeout(sssWriteFile, [this, { uw, cid, key, ver, syncwait }, bytes], { timeout, cancel });
    }

    async readFile(uw, cid, { key, ver, syncwait = syncwait_default }, { timeout, cancel } = {}) {
        check_args({ object: { uw }, string: { cid, key }, length_opt: { ver, syncwait, timeout }, promise_opt: { cancel } });
        ver = ver || undefined;
        return call_with_timeout(sssReadFile, [this, { uw, cid, key, ver, syncwait }], { timeout, cancel });
    }
}

module.exports = { version, concatUint8Arrays, composeUint8Arrays, decomposeUint8Arrays, makeRandomUint8Array, sha256, getBytesByPBKDF2, encryptAES, decryptAES, generateECDSAKey, generateRSAKey, importPrivateKey, importPublicKey, importPublicKeyFromRsaPem, signSignature, verifySignature, callHTTP, isValidUnicodeString, encodeUTF8, decodeUTF8, encodeBase16, decodeBase16, encodeBase32, decodeBase32, encodeBase64, decodeBase64, encodeBase64url, decodeBase64url, encodeBase57, decodeBase57, encodePEM, decodePEM, makeRandomText, setEthersModule, setXmlDSigJsModule, getWalletAddress, isValidWalletAddressFormat, importSigningWallet, importVerifyingWallet, generateWalletKey, getWalletDescription, pluginExternalWalletModule, parseWalletFile, parseUnlockedWalletFile, unlockWalletFile, createWalletFile, lockWalletFile, makeHASH, makeTXID, isValidTXIDFormat, createRequest, signRequest, parseRequest, verifyRequestSignatures, packRequest, unpackRequest, getTypeofId, isMemberId, isObjectId, isKeyword, isRelateId, isValidDGAL, isAclGroupId, isAclGroupMemberId, isObjectName, isUnifiedName, isStatusString, getHashAnchors, calculateTxHash, calculateBlockHash, createSocket, loadPeersCnf, verifyPeersCnfUpdate, RPC, callRequest, fetchBlock, fetchTxHash, fetchTxHashes, fetchCnfstr, fetchTxSPV, fetchBlockSPV, verifySPV1, verifySPV2sigs, verifySPV2chain, verifySPV, updatePeersCnf, postAttachment, getAttachment, callStorage, callRequest_ex, fetchBlock_ex, fetchTxHash_ex, fetchTxHashes_ex, fetchCnfstr_ex, fetchTxSPV_ex, fetchBlockSPV_ex, verifySPV_ex, updatePeersCnf_ex, postAttachment_ex, getAttachment_ex, callStorage_ex, sssDistribute, sssRevert, StorageSSS };
