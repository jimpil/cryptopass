(ns cryptopass.impl.pbkdf2-test
  (:require [cryptopass.impl.pbkdf2 :as pbkdf2]
            [clojure.test :refer :all]))

(deftest pbkdf2-roundtrip
  (let [pwd "super-strong-password!"
        db-data (pbkdf2/hash-pwd (.toCharArray pwd) {})]
    (is (true?  (pbkdf2/matches? (.toCharArray pwd) db-data {})))
    (is (false? (pbkdf2/matches? (.toCharArray "no-way!") db-data {})))
    )
  )
