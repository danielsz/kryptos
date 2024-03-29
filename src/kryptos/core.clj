(ns kryptos.core
  (:require [pandect.algo.sha256 :refer [sha256-hmac sha256-hmac-bytes]]
            [digest])
  (:import javax.crypto.spec.SecretKeySpec
           javax.crypto.KeyGenerator
           java.util.Base64
           java.security.MessageDigest
           java.security.spec.X509EncodedKeySpec
           java.security.KeyFactory))

(defn digest [xs]
  (digest/md5 (apply str (sort xs))))

(defn generate-symmetric-key []
  (let [generator (KeyGenerator/getInstance "HmacSHA256")]
    (.generateKey generator)))

;; one-way hash

(defmulti sign (fn [key data] (type key)))
(defmethod sign javax.crypto.spec.SecretKeySpec [key data]
  (sha256-hmac data (.getEncoded key)))
(defmethod sign java.lang.String [key data]
  (sha256-hmac data key))

(defn verify-hmac [key data hmac]
  (= hmac (sign key data)))

(defmulti sign-bytes (fn [key data] (type key)))
(defmethod sign-bytes javax.crypto.spec.SecretKeySpec [key data]
  (sha256-hmac-bytes data (.getEncoded key)))
(defmethod sign-bytes java.lang.String [key data]
  (sha256-hmac-bytes data key))

(defn verify-hmac-bytes [key data hmac]
  (= (seq hmac) (seq (sign-bytes key data))))

(defprotocol Baze64
  (encode-base64 [x])
  (encode-base64-without-padding [x])
  (encode-base64-url [x])
  (encode-base64-url-without-padding [x])
  (decode-base64 [s target])
  (decode-base64-url [s]))

(extend-type String
  Baze64
  (encode-base64 [s]
    (.encodeToString (Base64/getEncoder) (.getBytes s)))
  (encode-base64-without-padding [s]
    (-> (Base64/getEncoder) .withoutPadding (.encodeToString (.getBytes s))))
  (encode-base64-url [s]
    (.encodeToString (Base64/getUrlEncoder) (.getBytes s)))
  (encode-base64-url-without-padding [s]
    (-> (Base64/getUrlEncoder) .withoutPadding (.encodeToString (.getBytes s))))
  (decode-base64 [s target]
    (case target
      :string (String. (.decode (Base64/getDecoder) s) "UTF-8")
      :key (let [bytes (.decode (Base64/getDecoder) s)]
             (SecretKeySpec. bytes 0 (count bytes) "HmacSHA256"))
      "no target given"))
  (decode-base64-url [s]
    (String. (.decode (Base64/getUrlDecoder) s) "UTF-8")))

(extend-type SecretKeySpec
  Baze64
  (encode-base64 [key]
    (.encodeToString (Base64/getEncoder) (.getEncoded key))))

(extend-type (Class/forName "[B")
  Baze64
  (decode-base64-url [bytes]
    (.decode (Base64/getUrlDecoder) bytes))
  (encode-base64 [bytes]
    (.encodeToString (Base64/getEncoder) bytes))
  (encode-base64-without-padding [bytes]
    (-> (Base64/getEncoder) .withoutPadding (.encodeToString bytes)))
  (encode-base64-url [bytes]
    (.encodeToString (Base64/getUrlEncoder) bytes))
  (encode-base64-url-without-padding [bytes]
    (-> (Base64/getUrlEncoder) .withoutPadding (.encodeToString bytes))))

(defn new-telefunken-key []
  (let [key (generate-symmetric-key)]
    (encode-base64 key)))

(defn hash-dgst
  "Single arity is suitable for PKCE code challenge, next signature is Sun implementation where s is string, algo is SHA-224, SHA-256, etc."
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


(defn pem-string->public-key [s]
  (let [encoded (.decode (Base64/getDecoder) s)
        kf (KeyFactory/getInstance "RSA")
        key-spec (X509EncodedKeySpec. encoded)]
    (.generatePublic kf key-spec)))
