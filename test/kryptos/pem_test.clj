(ns kryptos.pem-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.string :as str]
            [kryptos.pem :as pem])
  (:import [java.security KeyPairGenerator]
           [java.util Arrays Base64]))

(defn- spki-der []
  (let [generator (doto (KeyPairGenerator/getInstance "RSA")
                    (.initialize 2048))]
    (.getEncoded (.getPublic (.generateKeyPair generator)))))

(defn- fold [^String s]
  (str/join "\n" (map #(apply str %) (partition-all 64 s))))

(defn- armor [^String s]
  (str "-----BEGIN PUBLIC KEY-----\n"
       (fold s)
       "\n-----END PUBLIC KEY-----\n"))

(defn- ex-type [f]
  (:type (try
           (f)
           nil
           (catch clojure.lang.ExceptionInfo e (ex-data e)))))

(deftest pem-string->public-key-test
  (let [der (spki-der)
        b64 (.encodeToString (Base64/getEncoder) der)]
    (testing "armored PEM"
      (let [key (pem/pem-string->public-key (armor b64))]
        (is (= "RSA" (.getAlgorithm key)))
        (is (Arrays/equals der (.getEncoded key)))))
    (testing "bare base64"
      (is (Arrays/equals der (.getEncoded (pem/pem-string->public-key b64)))))
    (testing "folded bare base64"
      (is (Arrays/equals der (.getEncoded (pem/pem-string->public-key (fold b64))))))
    (testing "explicit algorithm"
      (is (Arrays/equals der (.getEncoded (pem/pem-string->public-key (armor b64) "RSA")))))
    (testing "explicit algorithm mismatch"
      (is (= ::pem/unsupported-pem
             (ex-type #(pem/pem-string->public-key (armor b64) "EC")))))))

(deftest unsupported-pem-test
  (testing "PKCS#1 RSA keys are rejected"
    (is (= ::pem/unsupported-pem
           (ex-type #(pem/pem-string->public-key
                      "-----BEGIN RSA PUBLIC KEY-----\nAAAA\n-----END RSA PUBLIC KEY-----")))))
  (testing "other PEM labels are rejected"
    (is (= ::pem/unsupported-pem
           (ex-type #(pem/pem-string->public-key
                      "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"))))))

(deftest invalid-pem-test
  (testing "invalid base64 length"
    (is (= ::pem/invalid-pem
           (ex-type #(pem/pem-string->public-key
                      "-----BEGIN PUBLIC KEY-----\nAAAAA\n-----END PUBLIC KEY-----")))))
  (testing "decodable but not a key"
    (is (= ::pem/unsupported-pem
           (ex-type #(pem/pem-string->public-key "!!!!"))))))
