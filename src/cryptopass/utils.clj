(ns cryptopass.utils
  (:require [cryptopass.core :refer [*stealth?*]])
  (:import (java.security SecureRandom)
           (java.util Arrays Base64 Base64$Decoder Base64$Encoder)
           (java.nio CharBuffer ByteBuffer)
           (java.nio.charset Charset)))

(defn secure-random-bytes
  "Returns <n> (cryptographically strong) random bytes."
  (^bytes [n]
   (secure-random-bytes n (SecureRandom.)))
  (^bytes [^long n ^SecureRandom sr]
   (let [^bytes random-bs (byte-array n)]
     (.nextBytes (or sr (SecureRandom.)) random-bs)
     random-bs)))

(defn chars->bytes
  "Given an array of characters <cs> and some character-encoding <encoding>
   returns the corresponding bytes, optionally without leaving any traces of the conversion
   (e.g. allocating a String object)."
  ^bytes [^String encoding ^chars cs]
   (let [char-buffer (CharBuffer/wrap cs)
         byte-buffer (.encode (Charset/forName encoding) char-buffer)
         ret (Arrays/copyOfRange (.array byte-buffer)
                                 (.position byte-buffer)
                                 (.limit byte-buffer))]
     (when *stealth?*
       (Arrays/fill (.array byte-buffer) (byte 0)))
     ret))

(defn bytes->chars
  "Given an array of bytes <bs> and some character-encoding <encoding>
   returns the correspond characters, optionally without leaving any traces of the conversion
   (e.g. allocating a String object)."
  ^chars [^String encoding ^bytes bs]
   (let [byte-buffer (ByteBuffer/wrap bs)
         char-buffer (.decode (Charset/forName encoding) byte-buffer)
         ret (Arrays/copyOfRange (.array char-buffer)
                                 (.position char-buffer)
                                 (.limit char-buffer))]
     (when *stealth?*
       (Arrays/fill (.array char-buffer) \u0000))
     ret))

(defn bytes->base64-str
  "Encodes the specified byte array into a String using the Base64 encoding scheme."
  (^String [^bytes bs]
   (bytes->base64-str bs :plain))
  (^String [^bytes bs encoder]
   (bytes->base64-str bs encoder "UTF-8"))
  (^String [^bytes bs encoder char-encoding]
   (let [^Base64$Encoder enc (case encoder
                               :mime (Base64/getMimeEncoder)
                               :url  (Base64/getUrlEncoder)
                               :plain (Base64/getEncoder)
                               encoder)
         res (.encode enc bs)]
     (String. res (Charset/forName char-encoding)))))

(defn base64-str->bytes
  "Decodes a Base64 encoded String into a byte array using the Base64 encoding scheme."
  (^bytes [^String s]
   (base64-str->bytes s :plain))
  (^bytes [^String s decoder]
   (let [^Base64$Decoder deco (case decoder
                                :mime (Base64/getMimeDecoder)
                                :url  (Base64/getUrlDecoder)
                                :plain (Base64/getDecoder)
                                decoder)]
     (.decode deco s))))

(defn aconcat-chars!
  "Concatenates two arrays <a1> & <a2> into a new one and returns it.
   Optionally clears the two input arrays."
  ^chars [^chars a1 ^chars a2]
  (let [a1-length (alength a1)
        a2-length (alength a2)
        ret (char-array (unchecked-add-int a1-length a2-length))]
    (System/arraycopy a1 0 ret 0 a1-length)
    (System/arraycopy a2 0 ret a1-length a2-length)
    (when *stealth?*
      (Arrays/fill a1 \u0000)
      (Arrays/fill a2 \u0000))
    ret))
