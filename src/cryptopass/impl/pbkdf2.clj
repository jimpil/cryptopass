(ns cryptopass.impl.pbkdf2
  (:require [cryptopass.utils :as ut]
            [clojure.string :as str])
  (:import (javax.crypto.spec PBEKeySpec)
           (javax.crypto SecretKeyFactory)
           (java.util Arrays)))

(set! *warn-on-reflection* true)
(set! *unchecked-math* :warn-on-boxed)

(def pbkdf2-algorithms
  "The two supported PBKDF2 algorithms specified by keys :hmac-sha1 & :hmac-sha256 (JDK8)."
  {:hmac-sha1   "PBKDF2WithHmacSHA1"
   :hmac-sha256 "PBKDF2WithHmacSHA256"})

(defn- aconcat-chars!
  ^chars [^chars a1 ^chars a2]
  (let [a1-length (alength a1)
        a2-length (alength a2)
        ret (char-array (unchecked-add-int a1-length a2-length))]
    (System/arraycopy a1 0 ret 0 a1-length)
    (System/arraycopy a2 0 ret a1-length a2-length)
    (Arrays/fill a1 \u0000)
    (Arrays/fill a2 \u0000)
    ret))

(defn hash-pwd
  "Get a PBKDF2 (key-stretching) hash for the given string <pwd>.
   A good/similar alternative to bcrypt. Options include:

  :algo - The algorithm to use. See `treajure.crypto-hashing/pbkdf2-algorithms`
          for the supported algorithms. Defaults to `:hmac-sha256`.

  :salt - The salt to use (a byte-array or String). Defaults to 10 random bytes (generated via `SecureRandom`).

  :key-length - How long the key should be. Defaults to 192 (bits).

  :iterations - How many iterations to use. The bigger this is, the more expensive the calculation.
                Defaults to 2000.

  Returns the hashed password prefixed with salt (in base64), the iterations and the key-length."

  [^chars pwd {:keys [algo salt key-length iterations encoding]
               :or {algo :hmac-sha256 ;; prefer this please
                    iterations 2000 ;; 2000 iterations is a reasonable starting point
                    key-length 192  ;; 192-bit long
                    encoding "UTF-8"
                    salt (ut/secure-random-bytes 10)}}] ;; 10 random bytes (generated from a cryptographically secure source)
  (assert (contains? pbkdf2-algorithms algo)
          "Algorithm not recognised! :hmac-sha1 & :hmac-sha256 (starting with JDK8) are supported.")

  (let [[^bytes salt-bytes salt-chars] (cond
                                         (bytes? salt)
                                         [salt
                                          (ut/bytes->chars true encoding salt)]

                                         (string? salt)
                                         [(.getBytes ^String salt ^String encoding)
                                          (.toCharArray ^String salt)]

                                         :else
                                         (throw (IllegalArgumentException. ":salt can be either a String or a byte-array.")))
        ;; prepend the salt to the hash
        salt+x-chars (aconcat-chars! salt-chars pwd) ;; this call will clear both args
        f (SecretKeyFactory/getInstance (algo pbkdf2-algorithms))
        k (PBEKeySpec. salt+x-chars salt-bytes iterations key-length)
        salt-b64 (ut/bytes->base64-str salt :plain encoding)
        hashed-pwd (-> (.generateSecret f k) .getEncoded (ut/bytes->base64-str :plain encoding))]
    ;; we're done  - clear all the remaining arrays
    (Arrays/fill salt+x-chars \u0000)
    (Arrays/fill salt-bytes (byte 0))
    (str salt-b64 \$ iterations \$ key-length \$ hashed-pwd)))


(defn matches?
  "Given some <user-input>, a salt & a pbkdf2 hash (both fetched from DB in base64),
   returns true if the <user-input> matches the one contained in the hash.
   <opts> per `hash-pwd`."
  [^String user-input hashed-db opts]
  (let [[b64-salt iter key-length] (str/split hashed-db #"\$" 4)
        salt-bytes (ut/base64-str->bytes b64-salt)
        hashed (hash-pwd user-input (assoc opts :salt salt-bytes
                                                :key-length (Long/parseLong key-length)
                                                :iterations (Long/parseLong iter)))]
    (= hashed-db hashed)))

