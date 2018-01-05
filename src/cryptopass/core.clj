(ns cryptopass.core)

(defprotocol ICryptoHashable
  (hash-pwd* [this hash-fn options])
  (check-pwd* [this hash-fn-ret check-fn opts])
  )

(extend-protocol ICryptoHashable
  (Class/forName "[C")
  (hash-pwd* [this hash-fn opts]
    (hash-fn this opts))
  (check-pwd* [this hash-fn-ret check-fn opts]
    (check-fn this hash-fn-ret opts))

  String
  (hash-pwd* [this hash-fn opts]
    (hash-fn this opts))
  (check-pwd* [this hash-fn-ret check-fn opts]
    (check-fn this hash-fn-ret opts))

  )

(defn hash-pwd
  [pwd hash-fn opts]
  (hash-pwd* pwd hash-fn opts))

(defn check-pwd
  [pwd hash-fn-ret check-fn opts]
  (check-pwd* pwd hash-fn-ret check-fn opts))


(comment
  ;; suppose we want pbkdf2 hashing
  (let [hash-fn cryptopass.impl.pbkdf2/hash-pwd
        check-fn cryptopass.impl.pbkdf2/matches?]

    )


  )
