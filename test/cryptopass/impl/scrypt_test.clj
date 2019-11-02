(ns cryptopass.impl.scrypt-test
  (:require [clojure.test :refer :all]
            [cryptopass.impl.scrypt :refer :all]
            [cryptopass.utils :as ut])
  (:import [cryptopass.cryptopass.jscrypt SCrypt]))


(deftest scrypt-paper-appendix-b
  (testing "password/NaCl"
    (let [P (.toCharArray "password")
          S (.getBytes "NaCl" "UTF-8")
          N 1024
          r 8
          p 16
          dklen 64
          DK "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"]
      (is (= (seq (hash-pwd P S {:N N :r r :p p :dklen dklen}))
             (seq (ut/base64-str->bytes DK))))
      )
    )


  )
