(ns kryptos.jwt
  (:require [kryptos.core :as crypto]
            [kryptos.helpers :refer [string->utf8-bytes]]
            [clojure.string :as str]
            [clojure.data.json :as json])
  (:import [java.security MessageDigest]
           [java.time Instant]
           [java.net URI]
           [clojure.lang ExceptionInfo]))

(defn- token-segments
  "Splits a token into its 3 raw (still base64url-encoded) segments.
   Throws ex-info {:type :malformed-token} if there aren't exactly 3."
  [token]
  (let [parts (str/split (str token) #"\.")]
    (when-not (= 3 (count parts))
      (throw (ex-info "Malformed token: expected header.claims.signature"
                       {:type :malformed-token :segment-count (count parts)})))
    parts))

(defn decode-jwt
  "Decodes a token into [header-json claims-json signature-bytes].

   Header and claims are UTF-8 text; the signature is returned as raw bytes,
   since it is binary and must not be UTF-8-decoded."
  [token]
  (try
    (let [[h c s] (token-segments token)]
      [(crypto/decode-base64-url h)
       (crypto/decode-base64-url c)
       (crypto/decode-base64-url s :bytes)])
    (catch ExceptionInfo e (throw e))
    (catch Exception e
      (throw (ex-info "Malformed token: invalid base64url segment"
                       {:type :malformed-token} e)))))

(defn- parse-json [s]
  (try
    (json/read-str s :key-fn keyword)
    (catch Exception e
      (throw (ex-info "Malformed token: invalid JSON segment"
                      {:type :malformed-token} e)))))

(defn headers
  "Returns the decoded header map of `token`."
  [token]
  (let [[headers _ _] (decode-jwt token)]
    (parse-json headers)))

(defn claims
  "Returns the decoded claims map of `token`, or the value at key `k`."
  ([token]
   (let [[_ claims _] (decode-jwt token)]
     (parse-json claims)))
  ([token k]
    (k (claims token))))

(defn signature
  "Returns the raw signature bytes."
  [token]
  (nth (decode-jwt token) 2))

(defn valid-audience?
  "Returns true when `client` matches `aud`, which may be a single value
  or a collection of acceptable values."
  [aud client]
  (if (sequential? aud) (contains? (set aud) client) (= client aud)))

(defn compute-signature
  "Returns the unpadded base64url HMAC-SHA256 of `header.claims` under
  `secret`."
  [header claims secret]
  (crypto/encode-base64-url-without-padding
   (crypto/sign-bytes secret (string->utf8-bytes (str header "." claims)))))

(defn valid-signature?
  "Returns true when the signature in `token` matches the HMAC-SHA256 of its
  header and claims under `secret`."
  [token secret]
  (let [[header claims sig] (token-segments token)]
    (MessageDigest/isEqual (string->utf8-bytes sig)
                           (string->utf8-bytes (compute-signature header claims secret)))))

(defn valid-nbf?
  "Returns true when `nbf` is not later than now plus `clock-tolerance`
  seconds (default 20)."
  [nbf & {:keys [clock-tolerance] :or {clock-tolerance 20}}]
  (< (- nbf (.getEpochSecond (java.time.Instant/now))) clock-tolerance))


(defn- safe-host
  "Host of a URL string, or nil if it's missing or unparseable — never throws."
  [url-str]
  (when url-str
    (try (.getHost (URI. url-str))
         (catch Exception _))))


(defn checks
  "Returns a map describing the validity of `token`: :not-expired?,
  :valid-nbf?, :valid-audience?, :valid-dest?, and :valid-signature?.
  Malformed tokens return {:validity false :error ...}."
  [token client secret]
  (try (let [c (claims token)
             dest (safe-host (:dest c))
             iss  (safe-host (:iss c))]
         {:not-expired?     (if-let [exp (:exp c)]
                              (> exp (.getEpochSecond (Instant/now)))
                              true)
          :valid-nbf?       (if-let [nbf (:nbf c)]
                              (valid-nbf? nbf)
                              true)
          :valid-audience?  (valid-audience? (:aud c) client)
          :valid-dest?      (boolean (and dest iss (= dest iss)))
          :valid-signature? (valid-signature? token secret)})
       (catch ExceptionInfo e {:validity false :error (ex-data e)})
       (catch Exception e {:validity false :error (.getMessage e)})))

(defn valid-token?
  "Returns true when every check for `token` passes."
  [token client secret]
  (every? true? (vals (checks token client secret))))

(defn debug-token
  "Returns the result of `checks` for `token`, including failure details."
  [token client secret]
  (checks token client secret))

