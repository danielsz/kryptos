(ns kryptos.jwt-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.data.json :as json]
            [clojure.string :as str]
            [kryptos.core :as crypto]
            [kryptos.jwt :as jwt])
  (:import [java.util Arrays Base64]))

(def secret "your-256-bit-secret")

(def header-seg "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
(def claims-seg "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ")
(def sig-seg "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
(def token (str header-seg "." claims-seg "." sig-seg))

(defn- make-token [header claims secret]
  (let [h (crypto/encode-base64-url-without-padding (json/write-str header))
        c (crypto/encode-base64-url-without-padding (json/write-str claims))]
    (str h "." c "." (jwt/compute-signature h c secret))))

(defn- now [] (.getEpochSecond (java.time.Instant/now)))

(deftest decode-test
  (testing "headers"
    (is (= {:alg "HS256" :typ "JWT"} (jwt/headers token))))
  (testing "claims"
    (is (= {:sub "1234567890" :name "John Doe" :iat 1516239022}
           (jwt/claims token)))
    (is (= 1516239022 (jwt/claims token :iat)))))

(deftest compute-signature-test
  (is (= sig-seg (jwt/compute-signature header-seg claims-seg secret))))

(deftest valid-signature-test
  (testing "known HS256 token"
    (is (true? (jwt/valid-signature? token secret))))
  (testing "wrong secret"
    (is (false? (jwt/valid-signature? token "wrong-secret"))))
  (testing "tampering with any segment"
    (is (false? (jwt/valid-signature? (str "x" header-seg "." claims-seg "." sig-seg)
                                      secret)))
    (is (false? (jwt/valid-signature? (str header-seg "." claims-seg "x." sig-seg)
                                      secret)))
    (is (false? (jwt/valid-signature? (str header-seg "." claims-seg "." "A" (subs sig-seg 1))
                                      secret)))))

(deftest signature-test
  (testing "signature returns the raw signature bytes"
    (let [sig (jwt/signature token)]
      (is (bytes? sig))
      (is (= 32 (alength sig)))
      (is (Arrays/equals (.decode (Base64/getUrlDecoder) sig-seg) sig))))
  (testing "decode-jwt returns header/claims text and signature bytes"
    (let [[h c s] (jwt/decode-jwt token)]
      (is (string? h))
      (is (string? c))
      (is (bytes? s)))))

(deftest valid-token-test
  (let [valid (make-token {:alg "HS256" :typ "JWT"}
                          {:aud "client"
                           :iss "https://shop.example"
                           :dest "https://shop.example"
                           :exp (+ (now) 3600)}
                          secret)]
    (testing "fully valid token"
      (is (true? (jwt/valid-token? valid "client" secret))))
    (testing "wrong audience"
      (is (false? (jwt/valid-token? valid "other" secret))))
    (testing "wrong secret"
      (is (false? (jwt/valid-token? valid "client" "wrong-secret"))))
    (testing "tampered claims"
      (let [[h _ s] (str/split valid #"\.")
            tampered (str h "."
                          (crypto/encode-base64-url-without-padding
                           (json/write-str {:aud "client"
                                            :iss "https://shop.example"
                                            :dest "https://shop.example"
                                            :exp (+ (now) 3600)
                                            :admin true}))
                          "." s)]
        (is (false? (jwt/valid-token? tampered "client" secret)))))
    (testing "expired"
      (let [expired (make-token {:alg "HS256" :typ "JWT"}
                                {:aud "client"
                                 :iss "https://shop.example"
                                 :dest "https://shop.example"
                                 :exp (- (now) 10)}
                                secret)]
        (is (false? (jwt/valid-token? expired "client" secret)))))
    (testing "mismatched dest/iss hosts"
      (let [mismatched (make-token {:alg "HS256" :typ "JWT"}
                                   {:aud "client"
                                    :iss "https://shop.example"
                                    :dest "https://evil.example"
                                    :exp (+ (now) 3600)}
                                   secret)]
        (is (false? (jwt/valid-token? mismatched "client" secret)))))))

(deftest malformed-token-test
  (testing "valid-token? returns false instead of throwing"
    (is (false? (jwt/valid-token? "not-a-token" "client" secret)))
    (is (false? (jwt/valid-token? "a.b" "client" secret)))
    (is (false? (jwt/valid-token? (str header-seg "."
                                       (crypto/encode-base64-url-without-padding "not json")
                                       ".sig")
                                   "client" secret))))
  (testing "checks reports the error shape"
    (let [result (jwt/checks "not-a-token" "client" secret)]
      (is (false? (:validity result)))
      (is (some? (:error result))))))

(deftest checks-test
  (let [result (jwt/checks token "client" secret)]
    (testing "missing exp/nbf are accepted"
      (is (true? (:not-expired? result)))
      (is (true? (:valid-nbf? result))))
    (testing "missing aud/dest are rejected"
      (is (false? (:valid-audience? result)))
      (is (false? (:valid-dest? result))))
    (testing "signature still verifies"
      (is (true? (:valid-signature? result))))))

(deftest valid-audience-test
  (is (true? (jwt/valid-audience? "client" "client")))
  (is (false? (jwt/valid-audience? "client" "other")))
  (is (true? (jwt/valid-audience? ["a" "client"] "client")))
  (is (false? (jwt/valid-audience? ["a"] "client")))
  (is (false? (jwt/valid-audience? nil "client"))))

(deftest valid-nbf-test
  (let [n (now)]
    (is (true? (jwt/valid-nbf? n)))
    (is (true? (jwt/valid-nbf? (+ n 10))))
    (is (false? (jwt/valid-nbf? (+ n 30))))
    (testing "explicit tolerance"
      (is (true? (jwt/valid-nbf? (+ n 5) :clock-tolerance 10)))
      (is (false? (jwt/valid-nbf? (+ n 15) :clock-tolerance 10))))))
