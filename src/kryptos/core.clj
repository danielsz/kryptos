(ns kryptos.core
  (:require [pandect.algo.sha256 :refer [sha256-hmac sha256-hmac-bytes]]
            [kryptos.helpers :refer [string->utf8-bytes bytes->hex]])
  (:import javax.crypto.spec.SecretKeySpec
           java.util.Base64
           java.security.MessageDigest
           java.security.spec.X509EncodedKeySpec
           java.security.KeyFactory
           javax.crypto.KeyGenerator))

(defprotocol Signer
  (sign [key data])
  (sign-bytes [key data]))

(extend-protocol Signer
  javax.crypto.spec.SecretKeySpec
  (sign [key data]       (sha256-hmac data (.getEncoded key)))
  (sign-bytes [key data] (sha256-hmac-bytes data (.getEncoded key)))

  String
  (sign [key data]       (sha256-hmac data key))
  (sign-bytes [key data] (sha256-hmac-bytes data key))

  byte/1
  (sign [key data]       (sha256-hmac data key))
  (sign-bytes [key data] (sha256-hmac-bytes data key)))

(defn verify-hmac [key data hmac]
  (= hmac (sign key data)))

(defn verify-hmac-constant-time [key data hmac]
  (let [expected (string->utf8-bytes (sign key data))
        supplied (string->utf8-bytes (str hmac))]
    (MessageDigest/isEqual expected supplied)))

(defn verify-hmac-bytes [key data hmac]
  (let [^bytes expected (sign-bytes key data)]
    (if (bytes? hmac)
      (let [^bytes supplied hmac]
        (MessageDigest/isEqual supplied expected))
      (= (seq hmac) (seq expected)))))

(defprotocol Base64Encode
  (encode-base64 [x])
  (encode-base64-without-padding [x])
  (encode-base64-url [x])
  (encode-base64-url-without-padding [x]))

(defprotocol Base64Decode
  (decode-base64 [s target])
  (decode-base64-url [s]))

(extend-protocol Base64Encode
  String
  (encode-base64 [s]
    (.encodeToString (Base64/getEncoder) (string->utf8-bytes s)))
  (encode-base64-without-padding [s]
    (-> (Base64/getEncoder) .withoutPadding (.encodeToString (string->utf8-bytes s))))
  (encode-base64-url [s]
    (.encodeToString (Base64/getUrlEncoder) (string->utf8-bytes s)))
  (encode-base64-url-without-padding [s]
    (-> (Base64/getUrlEncoder) .withoutPadding (.encodeToString (string->utf8-bytes s))))

  SecretKeySpec
  (encode-base64 [key]
    (.encodeToString (Base64/getEncoder) (.getEncoded key)))
  (encode-base64-without-padding [key]
    (-> (Base64/getEncoder) .withoutPadding (.encodeToString (.getEncoded key))))
  (encode-base64-url [key]
    (.encodeToString (Base64/getUrlEncoder) (.getEncoded key)))
  (encode-base64-url-without-padding [key]
    (-> (Base64/getUrlEncoder) .withoutPadding (.encodeToString (.getEncoded key))))

  byte/1
  (encode-base64 [bytes]
    (.encodeToString (Base64/getEncoder) bytes))
  (encode-base64-without-padding [bytes]
    (-> (Base64/getEncoder) .withoutPadding (.encodeToString bytes)))
  (encode-base64-url [bytes]
    (.encodeToString (Base64/getUrlEncoder) bytes))
  (encode-base64-url-without-padding [bytes]
    (-> (Base64/getUrlEncoder) .withoutPadding (.encodeToString bytes))))

(extend-protocol Base64Decode
  String
  (decode-base64 [s target]
    (case target
      :bytes  (.decode (Base64/getDecoder) s)
      :string (String. ^bytes (.decode (Base64/getDecoder) s) "UTF-8")
      :key    (let [^bytes bs (decode-base64 s :bytes)]
                (SecretKeySpec. bs 0 (alength bs) "HmacSHA256"))))
  (decode-base64-url [s]
    (String. (.decode (Base64/getUrlDecoder) s) "UTF-8"))

  byte/1
  (decode-base64 [bytes target]
    (case target
      :bytes  (.decode (Base64/getDecoder) bytes)
      :string (String. ^bytes (.decode (Base64/getDecoder) bytes) "UTF-8")
      :key    (let [^bytes bs (decode-base64 bytes :bytes)]
                (SecretKeySpec. bs 0 (alength bs) "HmacSHA256"))))
  (decode-base64-url [bytes]
    (.decode (Base64/getUrlDecoder) bytes)))

(defn hash-dgst
  "Single arity returns the raw SHA-256 digest, suitable for a PKCE code challenge.

  The 2-arity is legacy: it uses the platform default charset, drops leading zero
  bytes via BigInteger, and pads to only 32 characters, so its output is not
  fixed-width for SHA-224/SHA-256/etc. Prefer `hash-digest-hex` for new code."
  ([bytes]
   (let [md (MessageDigest/getInstance "SHA-256")]
     (.update md bytes 0 (alength bytes))
     (.digest md)))
  ([s algo]
   (let [md (MessageDigest/getInstance algo)
         message-digest (.digest md (.getBytes s))
         no (BigInteger. 1 message-digest)
         hashtext (.toString no 16)]
     (loop [s hashtext] (if  (< (.length s) 32) (recur (str "0" s)) s)))))

(defn hash-digest-hex
  "Returns the lowercase hex digest of `s` using `algo` (e.g. \"SHA-256\"),
  zero-padded to twice the digest length. Strings are encoded as UTF-8."
  [s algo]
  (let [md (MessageDigest/getInstance algo)]
    (bytes->hex (.digest md (string->utf8-bytes s)))))

(defn pem-string->public-key [s]
  (let [encoded (.decode (Base64/getDecoder) s)
        kf (KeyFactory/getInstance "RSA")
        key-spec (X509EncodedKeySpec. encoded)]
    (.generatePublic kf key-spec)))

(defn generate-symmetric-key []
  (let [generator (KeyGenerator/getInstance "HmacSHA256")]
    (.generateKey generator)))
