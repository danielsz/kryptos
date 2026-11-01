(ns kryptos.helpers-test
  (:require [clojure.test :refer [deftest is testing]]
            [kryptos.helpers :as h])
  (:import [java.nio.charset StandardCharsets]
           [java.nio ByteBuffer]))

(defn- thrown-data
  [f]
  (try
    (f)
    nil
    (catch clojure.lang.ExceptionInfo e (ex-data e))))

(deftest string->utf8-bytes-test
  (testing "ASCII"
    (is (= (vec (.getBytes "abc" StandardCharsets/UTF_8))
           (vec (h/string->utf8-bytes "abc")))))
  (testing "non-ASCII"
    (is (= (vec (.getBytes "héllo" StandardCharsets/UTF_8))
           (vec (h/string->utf8-bytes "héllo")))))
  (testing "empty"
    (is (zero? (alength (h/string->utf8-bytes ""))))))

(deftest bytes->hex-test
  (testing "empty"
    (is (= "" (h/bytes->hex (byte-array 0)))))
  (testing "leading zero and high bytes"
    (is (= "00010f10ff" (h/bytes->hex (byte-array [0 1 15 16 -1])))))
  (testing "ASCII"
    (is (= "616263" (h/bytes->hex (.getBytes "abc" StandardCharsets/UTF_8)))))
  (testing "non-ASCII"
    (is (= "c3a9" (h/bytes->hex (.getBytes "é" StandardCharsets/UTF_8))))))

(deftest ->byte-array-accepted-test
  (testing "nil"
    (is (nil? (h/->byte-array nil))))
  (testing "byte[] returned unchanged"
    (let [b (byte-array [-1 0 127])]
      (is (identical? b (h/->byte-array b)))))
  (testing "String encoded as UTF-8"
    (is (= (vec (h/string->utf8-bytes "abc"))
           (vec (h/->byte-array "abc")))))
  (testing "sequential signed bytes"
    (is (= [-1 0 127] (vec (h/->byte-array [-1 0 127])))))
  (testing "sequential unsigned octets"
    (is (= [-1 0 127] (vec (h/->byte-array [255 0 127]))))))

(deftest ->byte-array-rejected-test
  (testing "non-octet values"
    (doseq [v [[1.5] [1.0] [\a] ["1"] [256] [-129]]]
      (is (= ::h/not-octet (:type (thrown-data #(h/->byte-array v))))
          (str "expected ::not-octet for " (pr-str v)))))
  (testing "non-coercible types"
    (doseq [v [1.5 (int-array [1 2]) (ByteBuffer/allocate 1) :kw]]
      (is (= ::h/not-bytes (:type (thrown-data #(h/->byte-array v))))
          (str "expected ::not-bytes for " (pr-str v))))))
