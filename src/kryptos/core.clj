(ns kryptos.core
  (:require [pandect.algo.sha256 :refer [sha256-hmac sha256-hmac-bytes]]
            [kryptos.helpers :refer [string->utf8-bytes bytes->hex]])
  (:import javax.crypto.spec.SecretKeySpec
           java.util.Base64
           java.security.MessageDigest
           javax.crypto.KeyGenerator))

(defprotocol Signer
  "Computes HMAC-SHA256 signatures. The `key` argument may be a String,
  a javax.crypto.spec.SecretKeySpec, or a byte array."
  (sign [key data] "Returns the HMAC-SHA256 of `data` as a lowercase hex string.")
  (sign-bytes [key data] "Returns the HMAC-SHA256 of `data` as a byte array."))

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

(defn verify-hmac
  "Verifies a hex `hmac` against the HMAC-SHA256 of `data` under `key`.

  Compares the UTF-8 bytes of both hex strings with MessageDigest/isEqual,
  so the running time does not depend on where they first differ. Returns
  true when the values match, false otherwise."
  [key data hmac]
  (let [expected (string->utf8-bytes (sign key data))
        supplied (string->utf8-bytes (str hmac))]
    (MessageDigest/isEqual expected supplied)))

(defn- legacy-hmac->bytes
  "Normalizes a legacy MAC representation to a byte array, mirroring the
  element-wise numeric equality previously used. Returns nil when the value
  cannot match a byte-array MAC."
  [hmac]
  (when-let [xs (seq hmac)]
    (try
      (let [out (byte-array (count xs))]
        (loop [i 0 s xs]
          (if s
            (let [e (first s)]
              (if (and (integer? e) (<= -128 e 127))
                (do (aset out i (unchecked-byte (long e)))
                    (recur (inc i) (next s)))
                nil))
            out)))
      (catch ArithmeticException _ nil))))

(defn verify-hmac-bytes
  "Verifies a raw `hmac` against the HMAC-SHA256 of `data` under `key`.

  `hmac` may be a byte array or any seqable collection of byte values.
  Byte arrays and normalized collections are compared in constant time.
  Non-integers and values outside the signed-byte range never match.
  Returns true when the values match, false otherwise."
  [key data hmac]
  (let [^bytes expected (sign-bytes key data)
        ^bytes supplied (if (bytes? hmac) hmac (legacy-hmac->bytes hmac))]
    (if supplied
      (MessageDigest/isEqual supplied expected)
      false)))

(defprotocol Base64Encode
  "Encodes values as base64 text."
  (encode-base64 [x] "Returns standard base64 with padding.")
  (encode-base64-without-padding [x] "Returns standard base64 without padding.")
  (encode-base64-url [x] "Returns URL-safe base64 with padding.")
  (encode-base64-url-without-padding [x] "Returns URL-safe base64 without padding."))

(defprotocol Base64Decode
  "Decodes base64 text."
  (decode-base64 [s target]
    "Decodes standard base64. `target` is :bytes, :string, or :key.
     :string decodes as UTF-8; :key builds an HmacSHA256 SecretKeySpec.")
  (decode-base64-url [s] [s target]
    "Decodes URL-safe base64.

     The one-arity returns a String for String input and a byte array for
     byte-array input. `target` is :bytes, :string, or :key; :string decodes
     as UTF-8 and :key builds an HmacSHA256 SecretKeySpec."))

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
  (decode-base64-url
    ([s]
     (String. ^bytes (.decode (Base64/getUrlDecoder) s) "UTF-8"))
    ([s target]
     (case target
       :bytes  (.decode (Base64/getUrlDecoder) s)
       :string (decode-base64-url s)
       :key    (let [^bytes bs (decode-base64-url s :bytes)]
                 (SecretKeySpec. bs 0 (alength bs) "HmacSHA256")))))

  byte/1
  (decode-base64 [bytes target]
    (case target
      :bytes  (.decode (Base64/getDecoder) bytes)
      :string (String. ^bytes (.decode (Base64/getDecoder) bytes) "UTF-8")
      :key    (let [^bytes bs (decode-base64 bytes :bytes)]
                (SecretKeySpec. bs 0 (alength bs) "HmacSHA256"))))
  (decode-base64-url
    ([bytes]
     (.decode (Base64/getUrlDecoder) bytes))
    ([bytes target]
     (case target
       :bytes  (.decode (Base64/getUrlDecoder) bytes)
       :string (String. ^bytes (.decode (Base64/getUrlDecoder) bytes) "UTF-8")
       :key    (let [^bytes bs (decode-base64-url bytes :bytes)]
                 (SecretKeySpec. bs 0 (alength bs) "HmacSHA256"))))))

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
  zero-padded to twice the digest length.

  The one-arity accepts a byte array and uses SHA-256. The two-arity accepts
  a String (encoded as UTF-8) or a byte array, with an explicit algorithm."
  ([^bytes bytes]
   (let [md (MessageDigest/getInstance "SHA-256")]
     (bytes->hex (.digest md bytes))))
  ([s algo]
   (let [md (MessageDigest/getInstance algo)
         ^bytes input (if (bytes? s) s (string->utf8-bytes s))]
     (bytes->hex (.digest md input)))))

(defn generate-symmetric-key
  "Generates a new random HmacSHA256 key using the JCA default key size."
  []
  (let [generator (KeyGenerator/getInstance "HmacSHA256")]
    (.generateKey generator)))
