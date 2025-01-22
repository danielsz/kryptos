(ns kryptos.jwt
  (:require [kryptos.core :as crypto]
            [clojure.string :as str]
            [clojure.data.json :as json]
            [detijd.predicates :as time])
  (:import [java.net URL]))

(defn decode-jwt [token]
  (map #(crypto/decode-base64-url %) (str/split token #"\.")))

(defn headers [token]
  (let [[headers _ _] (decode-jwt token)]
    (json/read-str headers :key-fn keyword)))

(defn claims
  ([token]
   (let [[_ claims _] (decode-jwt token)]
     (json/read-str claims :key-fn keyword)))
  ([token k]
    (k (claims token))))

(defn signature [token]
  (let [[_ _ sig] (decode-jwt token)]
    sig))

(defn expired? [token]
  (let [exp (claims token :exp)]
    (time/in-past? exp)))

(def not-expired? (complement expired?))

(defn valid-client? [token client]
  (let [aud (claims token :aud)]
    (= client aud)))

(defn jwt-io [token secret]
  (let [[header claims _] (str/split token #"\.")]
    (crypto/encode-base64-url-without-padding (crypto/sign-bytes secret
                                                                 (.getBytes (str header "." claims))))))

(defn valid-signature? [token secret]
  (let [[_ _ sig] (str/split token #"\.")]
    (= sig (jwt-io token secret))))

(defn valid-nbf? [token] ;; clock-tolerance is 20 seconds
  (let [nbf (claims token :nbf)]
    (< (- nbf (.getEpochSecond (java.time.Instant/now))) 20)))

(defn valid-token? [token client secret]
  (let [claims (claims token)
        host (fn [url] (.getHost (URL. url)))]
    (and (not-expired? token)
         (valid-client? token client)
         (valid-nbf? token)
         (= (host (:dest claims)) (host (:iss claims)))
         (valid-signature? token secret))))

(defn debug-token [token client secret]
  (let [claims (claims token)
        host (fn [url] (.getHost (URL. url)))]
    {:expired? (expired? token)
     :valid-client? (valid-client? token client)
     :valid-nbf? (valid-nbf? token)
     :host-and-destination (= (host (:dest claims)) (host (:iss claims)))
     :valid-signature? (valid-signature? token secret)
     :nbf (- (:nbf claims) (.getEpochSecond (java.time.Instant/now)))}))
