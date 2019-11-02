(ns cryptopass.impl.scrypt
  (:require [cryptopass.utils :as ut]
            [cryptopass.core :refer [*stealth?*]])
  (:import (javax.crypto.spec SecretKeySpec)
           (javax.crypto Mac)
           (javax.crypto SecretKeyFactory)
           (java.util Arrays)))

;; A faithful port of the `scryptJ` method found in:
;; https://github.com/wg/scrypt/blob/master/src/main/java/com/lambdaworks/crypto/SCrypt.java

(set! *warn-on-reflection* true)
(set! *unchecked-math* :warn-on-boxed)

(defmacro ^:private blockxor
  ""
  [^bytes S Si ^bytes D Di len]
  `(dotimes [i# ~len]
     (let [Di# (unchecked-add ~Di i#)]
       (aset ~D Di#
             (byte (bit-xor (aget ~D Di#)
                            (aget ~S (unchecked-add ~Si i#))))))))

(defmacro ^:private R
  [a b]
  `(bit-or
     (bit-shift-left ~a ~b)
     (unsigned-bit-shift-right ~a (unchecked-subtract 32 ~b))))

(defn- integerify
  ^long [^bytes B  ^long Bi ^long r]
  (let [Bi (unchecked-add Bi (unchecked-multiply 64 (unchecked-dec (unchecked-multiply 2 r))))
         n (bit-and (aget B Bi) 0xff) ;; the Java impl adds 0 to Bi and left shifts 0 bits (wat?)
         n (bit-or n (bit-shift-left (bit-and (aget B (unchecked-inc Bi)) 0xff) 8))
         n (bit-or n (bit-shift-left (bit-and (aget B (unchecked-add Bi 2)) 0xff) 16))]
     (bit-or n (bit-shift-left (bit-and (aget B (unchecked-add Bi 3)) 0xff) 24))))

(defn- x!
  [^longs x i1 i2 i3 ri]
  (aset x i1 (bit-xor (aget x i1)
                      (R (unchecked-add (aget x i2)
                                        (aget x i3))
                         ^long ri))))

(defn- salsa20-8
  [^bytes B]
  (let [B32 (long-array 16)
        x   (long-array 16)]
    (dotimes [i 16]
      (let [k (unchecked-multiply 4 i)]
        (aset B32 i (bit-and (aget B k) 0xff))
        (aset B32 i (bit-or (aget B32 i) (bit-shift-left (bit-and (aget B (unchecked-inc k)) 0xff) 8)))
        (aset B32 i (bit-or (aget B32 i) (bit-shift-left (bit-and (aget B (unchecked-add 2 k)) 0xff) 16)))
        (aset B32 i (bit-or (aget B32 i) (bit-shift-left (bit-and (aget B (unchecked-add 3 k)) 0xff) 24))))
      )
    (System/arraycopy B32 0 x 0 16)
    ;;TODO: long `for` loop
    (dotimes [_ 4] ;; the java impl uses `for (i = 8; i > 0; i -= 2) {...}` (wat?)
      (x! x 4 0 12 7)    (x! x 8 4 0 9)
      (x! x 12 8 4 13)   (x! x 0 12 8 18)
      (x! x 9 5 1 7)     (x! x 13 9 5 9)
      (x! x 1 13 9 13)   (x! x 5 1 13 18)
      (x! x 14 10 6 7)   (x! x 2 14 10 9)
      (x! x 6 2 14 13)   (x! x 10 6 2 18)
      (x! x 3 15 11 7)   (x! x 7 3 15 9)
      (x! x 11 7 3 13)   (x! x 15 11 7 18)
      (x! x 1 0 3 7)     (x! x 2 1 0 9)
      (x! x 3 2 1 13)    (x! x 0 3 2 18)
      (x! x 6 5 4 7)     (x! x 7 6 5 9)
      (x! x 4 7 6 13)    (x! x 5 4 7 18)
      (x! x 11 10 9 7)   (x! x 8 11 10 9)
      (x! x 9 8 11 13)   (x! x 10 9 8 18)
      (x! x 12 15 14 7)  (x! x 13 12 15 9)
      (x! x 14 13 12 13) (x! x 15 14 13 18)
      )

    (dotimes [i 16]
      (aset B32 i (unchecked-add (aget B32 i) (aget x i))))

    (dotimes [i 16]
      (let [k (unchecked-multiply i 4)
            b32i (aget B32 i)]
        (aset B k (byte (bit-and (aget B32 i) 0xff)))
        (aset B (unchecked-inc k) (byte (bit-and (bit-shift-right b32i 8) 0xff)))
        (aset B (unchecked-add k 2) (byte (bit-and (bit-shift-right b32i 16) 0xff)))
        (aset B (unchecked-add k 3) (byte (bit-and (bit-shift-right b32i 24) 0xff)))))
    )
  )

(defn- blockmix-salsa8
  [^bytes BY ^long Bi ^long Yi ^long r]
  (let [^bytes X (byte-array 64)]
    (System/arraycopy BY (->> r
                              (unchecked-multiply 2)
                              unchecked-dec
                              (unchecked-multiply 64)
                              (unchecked-add Bi))

                      X 0 64)
    (dotimes [i (unchecked-multiply 2 r)]
      (let [k (unchecked-multiply i 64)]
        (blockxor BY k X 0 64)
        (salsa20-8 X)
        (System/arraycopy X 0 BY (unchecked-add Yi k) 64)))

    (dotimes [i r]
      (System/arraycopy BY (-> i
                               (unchecked-multiply 2)
                               (unchecked-multiply 64)
                               (unchecked-add Yi))
                        BY
                        (unchecked-add Bi (unchecked-multiply i 64))
                        64))

    (dotimes [i r]
      (System/arraycopy BY (-> i
                               (unchecked-multiply 2)
                               unchecked-inc
                               (unchecked-multiply 64)
                               (unchecked-add Yi))
                        BY
                        (-> i
                            (unchecked-add r)
                            (unchecked-multiply 64)
                            (unchecked-add Bi))
                        64))
    )
  )


(defn- smix
  [^bytes B Bi r N ^bytes V ^bytes XY]
  (let [Xi 0
        Yi (unchecked-multiply 128 ^long r)]
    (System/arraycopy B Bi XY Xi Yi)

    (dotimes [i N]
      (System/arraycopy XY Xi V (unchecked-multiply i Yi) Yi)
      (blockmix-salsa8 XY Xi Yi r))

    (dotimes [_ N]
      (let [j (bit-and (integerify XY Xi r) (unchecked-dec ^long N))]
        (blockxor V (unchecked-multiply j Yi) XY Xi Yi)
        (blockmix-salsa8 XY Xi Yi r)))

    (System/arraycopy XY Xi B Bi Yi))
  )

(defn- pbkdf2! [mac ^bytes S c DK dklen]
  (let [hlen (.getMacLength mac)
        U (byte-array hlen)
        T (byte-array hlen)
        block1 (byte-array (unchecked-add (alength S) 4))
        l (int (Math/ceil (/ dklen hlen)))
        r (unchecked-subtract dklen
                              (unchecked-multiply hlen (unchecked-dec l)))
        ]
    (System/arraycopy S, 0, block1, 0, (alength S))
    (doseq [i (range 1 (unchecked-inc l))]



      (.update mac block1)
      (.doFinal mac U 0)
      (System/arraycopy U 0 T 0 hlen)



      (System/arraycopy T 0 DK (* hlen (unchecked-dec i)) (if (= i l) r hlen)))

    )
  )

(defn hash-pwd
  "todo"
  [^chars pwd ^bytes salt-bs {:keys [^long N ^long ^long r ^long p dklen]
                              :as opts}]
  (let [mac (doto (Mac/getInstance "HmacSHA256")
              (.init (SecretKeySpec. (ut/chars->bytes "UTF-8" pwd) "HmacSHA256")))
        DK (byte-array dklen)
        B (byte-array (* 128 r p))
        XY (byte-array (unchecked-multiply 256 r))
        V  (byte-array (* 128 r N))]

    (pbkdf2! mac salt-bs 1 B (* p 128 r))
    (dotimes [i p]
        (smix B (* i 128 r) r N V XY))
    (pbkdf2! mac B 1 DK dklen)

    (when *stealth?*
      (Arrays/fill pwd \u0000)
      (Arrays/fill salt-bs (byte 0)))
    (ut/bytes->base64-str DK :plain "UTF-8")

    )
  )
