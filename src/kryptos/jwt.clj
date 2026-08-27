(ns kryptos.jwt
  (:require [kryptos.core :as crypto]
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

(defn decode-jwt [token]
  (try
    (mapv crypto/decode-base64-url (token-segments token))
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

(defn headers [token]
  (let [[headers _ _] (decode-jwt token)]
    (parse-json headers)))

(defn claims
  ([token]
   (let [[_ claims _] (decode-jwt token)]
     (parse-json claims)))
  ([token k]
    (k (claims token))))

(defn signature [token]
  (let [[_ _ sig] (decode-jwt token)]
    sig))

(defn valid-audience? [aud client]
  (if (sequential? aud) (contains? (set aud) client) (= client aud)))

(defn compute-signature [header claims secret]
  (crypto/encode-base64-url-without-padding (crypto/sign-bytes secret
                                                               (.getBytes (str header "." claims)))))

(defn valid-signature? [token secret]
  (let [[header claims sig]  (token-segments token)]
    (MessageDigest/isEqual (.getBytes ^String sig) (.getBytes ^String (compute-signature header claims secret)))))

(defn valid-nbf? [nbf & {:keys [clock-tolerance] :or {clock-tolerance 20}}]
  (< (- nbf (.getEpochSecond (java.time.Instant/now))) clock-tolerance))


(defn- safe-host
  "Host of a URL string, or nil if it's missing or unparseable — never throws."
  [url-str]
  (when url-str
    (try (.getHost (URI. url-str))
         (catch Exception _))))


(defn checks [token client secret]
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

 (defn valid-token? [token client secret]
   (every? true? (vals (checks token client secret))))

(defn debug-token [token client secret]
     (checks token client secret))

