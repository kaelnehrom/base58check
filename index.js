/*
 * @Author: zyc
 * @Date:   2016-09-11 23:36:05
 * @Last Modified by:   unrealce
 * @Last Modified time: 2016-09-13 01:26:13
 */
"use strict";

const base58 = require("bs58");

var sha256 = require("crypto-js/sha256");
var CryptoJs = require("crypto-js");

function toWordArray(buf) {
  return CryptoJs.lib.WordArray.create(buf);
}

function toBuffer(wa) {
  return Buffer.from(wa.toString(CryptoJs.enc.Hex), "hex");
}

function sha256x2(buffer) {
  var wa = toWordArray(buffer);
  var tmp = sha256(wa);
  return toBuffer(sha256(tmp));
}

module.exports.encode = (data, prefix = "00", encoding = "hex") => {
  if (typeof data === "string") {
    data = new Buffer(data, encoding);
  }
  if (!(data instanceof Buffer)) {
    throw new TypeError('"data" argument must be an Array of Buffers');
  }
  if (!(prefix instanceof Buffer)) {
    prefix = new Buffer(prefix, encoding);
  }
  let hash = Buffer.concat([prefix, data]);
  hash = sha256x2(hash);
  hash = Buffer.concat([prefix, data, hash.slice(0, 4)]);
  return base58.encode(hash);
};

module.exports.decode = (string, encoding) => {
  const buffer = new Buffer(base58.decode(string));
  let prefix = buffer.slice(0, 1);
  let data = buffer.slice(1, -4);
  let hash = Buffer.concat([prefix, data]);
  hash = sha256x2(hash);
  buffer.slice(-4).forEach((check, index) => {
    if (check !== hash[index]) {
      throw new Error("Invalid checksum");
    }
  });
  if (encoding) {
    prefix = prefix.toString(encoding);
    data = data.toString(encoding);
  }
  return { prefix, data };
};
