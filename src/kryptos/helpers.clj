(ns kryptos.helpers
  (:import [java.nio.charset StandardCharsets]))

(defn string->utf8-bytes
  "Returns String `s` encoded as UTF-8 byte[].
       The charset is explicit so results do not depend on the platform default."
  ^bytes [^String s]
  (.getBytes s StandardCharsets/UTF_8))

(defn bytes->hex
  "Returns the lowercase, zero-padded hex representation of byte array `bs`
  (two characters per byte)."
  ^String [^bytes bs]
  (apply str (map #(format "%02x" (bit-and (long %) 0xff)) bs)))

(defn- octet
  "Coerces an integral `v` in -128..255 to a signed byte.
       Accepts signed-byte (-128..-1) and unsigned-octet (0..255) values.  
       Rejects non-integers (e.g. 1.0, chars), non-numbers, and out-of-range
       values with ex-info {:type ::not-octet :value v}. Never truncates."
  [v]
  (if (and (integer? v) (<= -128 v 255))
    (unchecked-byte (long v))
    (throw (ex-info "Value is not an octet (-128..255)" {:type ::not-octet :value v}))))

(defn ->byte-array
  "Coerces `x` to byte[] for constant-time comparison.

       Accepted:
         - nil          -> nil
         - byte[]       -> unchanged
         - String       -> UTF-8 bytes (see string->utf8-bytes)
         - sequential   -> byte[] via octet (range-checked); octets 0..255 and signed
                           bytes -128..127 are both accepted

       Any other type throws ex-info {:type ::not-bytes :value x}."
  ^bytes [x]
  (cond
    (nil? x)   nil
    (bytes? x) x
    (string? x) (string->utf8-bytes x)
    (sequential? x) (byte-array (map octet x))
    :else (throw (ex-info "Cannot coerce to byte[]; pass a byte[], String, or sequential of octets (-128..255)" {:type ::not-bytes :value x}))))



