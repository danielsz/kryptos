(ns kryptos.pem
  (:require [clojure.string :as str])
  (:import [java.util Base64]
           [java.security KeyFactory NoSuchAlgorithmException]
           [java.security.spec InvalidKeySpecException X509EncodedKeySpec]))

(def ^:private spki-algorithms
  ["RSA" "EC" "DSA" "Ed25519" "Ed448" "X25519" "X448"])

(defn- pem-parts
  "Returns {:label ... :body ...} for armored PEM, or {:label nil :body s}."
  [s]
  (if-let [[_ label body]
           (re-find #"(?s)-----BEGIN ([^-]+)-----(.*?)-----END [^-]+-----"
                    (str s))]
    {:label (str/trim label) :body body}
    {:label nil :body (str s)}))

(defn- decode-pem-body
  "Decodes the base64 body, tolerating CRLF and line folding."
  ^bytes [body]
  (try
    (.decode (Base64/getMimeDecoder) body)
    (catch IllegalArgumentException e
      (throw (ex-info "Invalid base64 in public key"
                      {:type ::invalid-pem} e)))))

(defn- spki->public-key
  "Tries each JCA algorithm; the KeyFactory validates the DER algorithm OID."
  [^bytes der]
  (or (some (fn [algorithm]
              (try
                (.generatePublic (KeyFactory/getInstance algorithm)
                                 (X509EncodedKeySpec. der))
                (catch InvalidKeySpecException _ nil)
                (catch NoSuchAlgorithmException _ nil)))
            spki-algorithms)
      (throw (ex-info "Unsupported public key encoding or algorithm"
                      {:type ::unsupported-pem}))))

(defn pem-string->public-key
  "Parses a public key from a PEM string or bare base64 of a DER
  SubjectPublicKeyInfo.

  Accepts:
    - '-----BEGIN PUBLIC KEY-----' ... '-----END PUBLIC KEY-----' (SPKI)
    - bare base64 DER (no armor), with or without line folding

  The algorithm is detected from the DER (RSA, EC, DSA, Ed25519/Ed448,
  X25519/X448, whichever the running JDK supports).

  Throws ex-info {:type ::invalid-pem} for malformed base64, and
  {:type ::unsupported-pem} for unsupported labels, PKCS#1 RSA keys
  ('BEGIN RSA PUBLIC KEY'), or unknown algorithms."
  ([s]
   (pem-string->public-key s nil))
  ([s algorithm]
   (let [{:keys [label body]} (pem-parts s)]
     (cond
       (= "RSA PUBLIC KEY" label)
       (throw (ex-info "PKCS#1 RSA keys are not supported; use SubjectPublicKeyInfo (BEGIN PUBLIC KEY)"
                       {:type ::unsupported-pem :label label}))

       (and label (not= "PUBLIC KEY" label))
       (throw (ex-info (str "Unsupported PEM label: " label)
                       {:type ::unsupported-pem :label label}))

       algorithm
       (try
         (.generatePublic (KeyFactory/getInstance algorithm)
                          (X509EncodedKeySpec. (decode-pem-body body)))
         (catch InvalidKeySpecException e
           (throw (ex-info (str "Key does not match algorithm " algorithm)
                           {:type ::unsupported-pem :algorithm algorithm} e)))
         (catch NoSuchAlgorithmException e
           (throw (ex-info (str "Unknown key algorithm: " algorithm)
                           {:type ::unsupported-pem :algorithm algorithm} e))))

       :else
       (spki->public-key (decode-pem-body body))))))
