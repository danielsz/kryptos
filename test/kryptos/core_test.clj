(ns kryptos.core-test
  (:require [clojure.test :refer [deftest is testing]]
            [kryptos.core :as crypto])
  (:import [java.nio.charset StandardCharsets]
           [java.util Arrays Base64]
           [javax.crypto.spec SecretKeySpec]))

(def secret "s3cr3t")
(def data "the quick brown fox")

(deftest signer-test
  (testing "sign returns a 64-char hex String"
    (let [hex (crypto/sign secret data)]
      (is (string? hex))
      (is (= 64 (count hex)))))
  (testing "sign-bytes returns a 32-byte array"
    (let [raw (crypto/sign-bytes secret data)]
      (is (bytes? raw))
      (is (= 32 (alength raw)))))
  (testing "byte[] key agrees with String key"
    (let [k (.getBytes secret StandardCharsets/UTF_8)]
      (is (= (crypto/sign secret data) (crypto/sign k data)))
      (is (Arrays/equals (crypto/sign-bytes secret data)
                         (crypto/sign-bytes k data)))))
  (testing "different keys produce different MACs"
    (is (not= (crypto/sign secret data)
              (crypto/sign "other" data)))))

(deftest verify-hmac-test
  (let [hex (crypto/sign secret data)]
    (is (true? (crypto/verify-hmac secret data hex)))
    (is (false? (crypto/verify-hmac secret data (str hex "00"))))
    (is (false? (crypto/verify-hmac secret data nil)))))

(deftest verify-hmac-constant-time-test
  (let [hex (crypto/sign secret data)]
    (is (true? (crypto/verify-hmac-constant-time secret data hex)))
    (is (false? (crypto/verify-hmac-constant-time secret data (str hex "00"))))
    (is (false? (crypto/verify-hmac-constant-time secret data nil)))))

(deftest verify-hmac-bytes-test
  (let [raw (crypto/sign-bytes secret data)]
    (testing "accepted representations (legacy seq equality)"
      (is (true? (crypto/verify-hmac-bytes secret data raw)))
      (is (true? (crypto/verify-hmac-bytes secret data (vec raw))))
      (is (true? (crypto/verify-hmac-bytes secret data (seq raw))))
      (is (true? (crypto/verify-hmac-bytes secret data
                                           (int-array (map int raw))))))
    (testing "representations that never match under legacy semantics"
      (is (false? (crypto/verify-hmac-bytes
                   secret data
                   (mapv #(bit-and (long %) 0xff) raw))))
      (is (false? (crypto/verify-hmac-bytes
                   secret data
                   (String. raw StandardCharsets/UTF_8))))
      (is (false? (crypto/verify-hmac-bytes secret data nil)))
      (is (false? (crypto/verify-hmac-bytes
                   secret data (cons 0 (seq raw))))))))

(deftest string-base64-test
  (testing "standard alphabet"
    (is (= "aGVsbG8=" (crypto/encode-base64 "hello")))
    (is (= "aMOpbGxv" (crypto/encode-base64 "héllo")))
    (is (= "+/8=" (crypto/encode-base64 (byte-array [-5 -1])))))
  (testing "no padding"
    (is (= "aGVsbG8" (crypto/encode-base64-without-padding "hello"))))
  (testing "url-safe alphabet"
    (is (= "-_8=" (crypto/encode-base64-url (byte-array [-5 -1]))))
    (is (= "-_8" (crypto/encode-base64-url-without-padding (byte-array [-5 -1])))))
  (testing "URL encoding of plain text"
    (is (= "aGVsbG8=" (crypto/encode-base64-url "hello"))))
  (testing "decoding"
    (is (= "hello" (crypto/decode-base64 "aGVsbG8=" :string)))
    (is (= (vec (.getBytes "hello" StandardCharsets/UTF_8))
           (vec (crypto/decode-base64 "aGVsbG8=" :bytes))))
    (let [k (crypto/decode-base64 "aGVsbG8=" :key)]
      (is (instance? SecretKeySpec k))
      (is (Arrays/equals (.getBytes "hello" StandardCharsets/UTF_8)
                         (.getEncoded k))))
    (is (= "hello" (crypto/decode-base64-url "aGVsbG8=")))))

(deftest secret-key-base64-test
  (let [k  (crypto/generate-symmetric-key)
        bs (.getEncoded k)]
    (testing "all encoders run against the encoded key bytes"
      (is (= (.encodeToString (Base64/getEncoder) bs)
             (crypto/encode-base64 k)))
      (is (= (.encodeToString (.withoutPadding (Base64/getEncoder)) bs)
             (crypto/encode-base64-without-padding k)))
      (is (= (.encodeToString (Base64/getUrlEncoder) bs)
             (crypto/encode-base64-url k)))
      (is (= (.encodeToString (.withoutPadding (Base64/getUrlEncoder)) bs)
             (crypto/encode-base64-url-without-padding k))))))

(deftest byte-array-base64-test
  (let [b (byte-array [1 2 3])
        encoded (.getBytes "AQID" StandardCharsets/UTF_8)]
    (testing "encoders"
      (is (= "AQID" (crypto/encode-base64 b)))
      (is (= "AQID" (crypto/encode-base64-without-padding b)))
      (is (= "AQID" (crypto/encode-base64-url b)))
      (is (= "AQID" (crypto/encode-base64-url-without-padding b))))
    (testing "decode-base64-url returns bytes"
      (is (= [1 2 3] (vec (crypto/decode-base64-url encoded)))))
    (testing "decode-base64"
      (is (= [1 2 3] (vec (crypto/decode-base64 encoded :bytes))))
      (let [k (crypto/decode-base64 encoded :key)]
        (is (instance? SecretKeySpec k))
        (is (Arrays/equals b (.getEncoded k)))))))
