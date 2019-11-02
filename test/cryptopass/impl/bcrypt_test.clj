(ns cryptopass.impl.bcrypt-test
  (:require [clojure.test :refer :all]
            [cryptopass.impl.bcrypt :refer :all])
  (:import (clojure.lang PersistentVector)
           (java.util.concurrent.atomic AtomicInteger)
           (org.mindrot.jbcrypt BCrypt)))


(def ^:private test-vectors
  [;; every 4th vector we have a 10 round salt
   [ "",
    "$2a$06$DCq7YPn5Rq63x1Lad4cll.",
    "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s." ],
   [ "",
    "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.",
    "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye" ],
   [ "",
    "$2a$10$k1wbIrmNyFAPwPVPSVa/ze",
    "$2a$10$k1wbIrmNyFAPwPVPSVa/zecw2BCEnBwVS2GbrmgzxFUOqW9dk4TCW" ],
   [ "",
    "$2a$12$k42ZFHFWqBp3vWli.nIn8u",
    "$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO" ],
   [ "a",
    "$2a$06$m0CrhHm10qJ3lXRY.5zDGO",
    "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe" ],
   [ "a",
    "$2a$08$cfcvVd2aQ8CMvoMpP2EBfe",
    "$2a$08$cfcvVd2aQ8CMvoMpP2EBfeodLEkkFJ9umNEfPD18.hUF62qqlC/V." ],
   [ "a",
    "$2a$10$k87L/MF28Q673VKh8/cPi.",
    "$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u" ],
   [ "a",
    "$2a$12$8NJH3LsPrANStV6XtBakCe",
    "$2a$12$8NJH3LsPrANStV6XtBakCez0cKHXVxmvxIlcz785vxAIZrihHZpeS" ],
   [ "abc",
    "$2a$06$If6bvum7DFjUnE9p2uDeDu",
    "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i" ],
   [ "abc",
    "$2a$08$Ro0CUfOqk6cXEKf3dyaM7O",
    "$2a$08$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm" ],
   [ "abc",
    "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.",
    "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi" ],
   [ "abc",
    "$2a$12$EXRkfkdmXn2gzds2SSitu.",
    "$2a$12$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q" ],
   [ "abcdefghijklmnopqrstuvwxyz",
    "$2a$06$.rCVZVOThsIa97pEDOxvGu",
    "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC" ],
   [ "abcdefghijklmnopqrstuvwxyz",
    "$2a$08$aTsUwsyowQuzRrDqFflhge",
    "$2a$08$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz." ],
   [ "abcdefghijklmnopqrstuvwxyz",
    "$2a$10$fVH8e28OQRj9tqiDXs1e1u",
    "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq" ],
   [ "abcdefghijklmnopqrstuvwxyz",
    "$2a$12$D4G5f18o7aMMfwasBL7Gpu",
    "$2a$12$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG" ],
   [ "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
    "$2a$06$fPIsBO8qRqkjj273rfaOI.",
    "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO" ],
   [ "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
    "$2a$08$Eq2r4G/76Wv39MzSX262hu",
    "$2a$08$Eq2r4G/76Wv39MzSX262huzPz612MZiYHVUJe/OcOql2jo4.9UxTW" ],
   [ "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
    "$2a$10$LgfYWkbzEvQ4JakH7rOvHe",
    "$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS" ],
   [ "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
    "$2a$12$WApznUOJfkEGSmYRfnkrPO",
    "$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC" ]
   ])

(deftest hash-pwd-tests
  (testing "`hash-pwd`"
    (doseq [[plain salt expected] test-vectors]
      (is (= expected
             (hash-pwd plain salt)
             (BCrypt/hashpw plain salt)))))

  (testing "`hash-pwd` with international characters"
    (let [pw1 "\u2605\u2605\u2605\u2605\u2605\u2605\u2605\u2605"
          pw2 "????????"
          h1 (hash-pwd pw1 (gen-salt))
          h2 (hash-pwd pw2 (gen-salt))]
      (is (false? (pwd-matches? pw2 h1)))
      (is (false? (pwd-matches? pw1 h2))))
    )
  )


(deftest gen-salt-tests
  (testing "`gen-salt`"
    (let [off (AtomicInteger. 0)]
      (doseq [i (range 6 13 2) ;; 6, 8, 10, 12
              j (range (.getAndIncrement off) (count test-vectors) 4)]
        (assert (.startsWith (get-in test-vectors [j 1])
                             (str "$2a$" (cond->> i (< i 10) (str \0)) "$")))
        (let [plain (get-in test-vectors [j 0])
              salt (gen-salt i)
              hashed1 (hash-pwd plain salt)
              hashed2 (hash-pwd plain hashed1)
              hashed3 (BCrypt/hashpw plain salt)]
          (is (= hashed1 hashed2 hashed3))))))
  )

(deftest pwd-matches?-tests
  (testing "`pwd-matches?` success"
    (doseq [[plain _ expected] test-vectors]
      (is (true? (pwd-matches? plain expected)))))

  (testing "`pwd-matches?` failure"
    (doseq [[plain :as x] test-vectors]
      (let [broken-index (mod (+ 4 (.indexOf ^PersistentVector test-vectors x)) (count test-vectors))
            expected (get-in test-vectors [broken-index 2])]
        (is (false? (pwd-matches? plain expected)))))
    )
  )