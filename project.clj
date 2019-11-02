(defproject cryptopass "0.2.0-SNAPSHOT"
  :description "Cryptographic password hashers for Clojure (implemented in Clojure)."
  :url "https://github.com.com/jimpil/cryptopass"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.9.0"]]
  :java-source-paths ["src/cryptopass/jscrypt"]
  :profiles {:dev {:dependencies [[criterium "0.4.4"] ;; for performance profiling/comparison
                                  [org.mindrot/jbcrypt "0.4"]]}})
