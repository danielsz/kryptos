(ns kryptos.core
  (:require [pandect.algo.sha256 :refer :all]
            [digest])
  (:import javax.crypto.Cipher
           javax.crypto.spec.SecretKeySpec
           javax.crypto.KeyGenerator
           java.util.Base64))

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

(defprotocol Baze64
  (encode-base64 [x])
  (encode-base64-url [x])
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
