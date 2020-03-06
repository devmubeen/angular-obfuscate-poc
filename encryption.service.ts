
import { Injectable } from '@angular/core';
import * as padder from 'pkcs7-padding';
import * as BufferModule from 'buffer';
import * as Rijndael from 'rijndael-js';

declare var JSEncrypt: any;


@Injectable({
  providedIn: 'root'
})
export class EncryptionService {

  PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
  MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCreY5bSbwUVAdIJVB26cmjtHFw
  /yvKjrkyzqKh3HQLjV/230uPnyGWVva81PcOVBR7SdfPDa5SxQQJTwOyxRk3hJLC
  QJjTRB9jqt6FCbzxMIewt3+hBJ6XOM0dMoplS5VBAVU0zjrjLc2PGOkOrIYcpMUF
  l0zDpWkegglAlUjc7QIDAQAB
  -----END PUBLIC KEY-----`;

  secretKey = '';
  ivKey = '';
  possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'!@#$%^&*()?><.,|";

  constructor() { }

  getEncryptedParams(params) {


    let aesRequestParamCipher = this.aesRequestBodyEncryption(params);

    let rsaEncryptedsecretKey = this.rsaEncryption(this.secretKey);
    let rsaEncryptedIVKey = this.rsaEncryption(this.ivKey);

    // console.log('RSA Secret Key: ', rsaEncryptedsecretKey);
    // console.log('RSA IV: ', rsaEncryptedIVKey);
    //console.log(this.secretKey);


    let encryptedBody = {
      "Body": {
        "Transaction": {
          "data1": aesRequestParamCipher,
          "data2": this.secretKey,
          "data3": this.ivKey
        }
      }
    };
    return encryptedBody;
  }


  aesRequestBodyEncryption(requestParams) {

    for (var i = 0; i < 16; i++) {
      this.secretKey += this.possible.charAt(Math.floor(Math.random() * this.possible.length));
      this.ivKey += this.possible.charAt(Math.floor(Math.random() * this.possible.length));
    }

    let plainText = BufferModule.Buffer.from(JSON.stringify(requestParams));
    let padded = padder.pad(plainText, 16);
    const cipherobj = new Rijndael(this.secretKey, 'cbc');
    const ciphertext = BufferModule.Buffer.from(cipherobj.encrypt(padded, 128, this.ivKey));
    let aesBase64Cipher = ciphertext.toString("base64");
    return aesBase64Cipher;

  }


  rsaEncryption(toEncrypt) {

    const jsenc = new JSEncrypt();
    jsenc.setPublicKey(this.PUBLIC_KEY);
    let rsaCipher = jsenc.encrypt(toEncrypt);
    return rsaCipher;
  }


}
