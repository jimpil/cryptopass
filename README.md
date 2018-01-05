# cryptopass

An extensible Clojure library for crypto-hashing passwords using various schemes. Offers a Clojure native implementation/port of `org.mindort/jBCrypt` (v0.4), and a handy wrapper around the PBKDF2 api already present in the JDK. In addition, `cryptopass` supports something called `stealth mode` which is particularly useful when dealing with sensitive data like passwords (read on for details). Finally `cryptopass` tries really hard to be reflection and boxed-math free.  

## Where
FIXME


## Why
People often get paranoid about how long sensitive information stays in memory. On the JVM Strings are immutable. That's not a bad thing at all (quite the contrary actually), but it just means that how long a String stays in memory is **not** up to you. The GC will claim that piece of memory when it sees fit. On the contrary, arrays are mutable. Once you're done using an array, you can manually fill it with any garbage you like. Yes, it is possible that arrays being moved by the GC will leave stray copies in memory, but these will have a high chance of being overwritten quickly as they will reside in 'hotter' memory regions. That's the best we can do on the JVM to make things harder for an attacker. 

Unfortunately, if you're using `org.mindort/jBCrypt` today, you're stuck with Strings. `cryptopass` attempts to address that with `stealth-mode`, which is a fancy way of saying that there is a dynamic Var controlling whether utilities and implementations clear out any arrays containing sensitive info that they create. This will obviously work better if you use character array for the input password (rather than String for the aforementioned reason).   

[Follow this SO discussion for more](https://stackoverflow.com/questions/8881291/why-is-char-preferred-over-string-for-passwords)

## Performance
There is no point discussing the performance of _PBKDF2_ as it's only a wrapper. _BCrypt_ on the other hand has been ported from the ground up, and so a performance comparison is warranted. In a nutshell, despite having no boxed-math, the Clojure code tends to be around 17% slower (on average). On a good run it might be 15% slower, whereas on a bad run it could be up to 20% slower. Generally speaking, I've observed that the higher the workload (the log-rounds), the smaller the difference tends to be, but I've never seen it going below 15% slower. Similarly, I've never seen it going above 20% slower, so as far as my (non-scientific) measurements are concerned, expect a 15-20% performance impact from using `cryptopass.cljBCrypt` instead of `org.mindort/jBCrypt` directly. Given that crypto-hashing is intentionally expensive, this not a noticeable difference (if you ask me). 

The above observations/conclusions were drawn from repeatedly comparing the output from `criterium.core/quick-bench` expressions (the CLJ vs JAVA implementation each time). It should also be noted that `stealth-mode` was **off** during those benchmarks. It really would not be fair to have it on, as it's extra functionality. The same goes for the `cryptopass.core/ICryptoHashable` abstraction. It was **not** involved during the aforementioned benchmarks for the same reasons. 


## Usage

FIXME

## Implementing new hashing schemes
For `stealth-mode` to work as intended in your own hashers, you will have to use (or at least mimic), the utilities in `cryptopass.util.clj`. Depending on your use-case, you may even have to add expressions like `(when cryptopass.core/*stealth?* (Arrays.fill ...))` in key places of your code. You will basically need to do this for every array holding sensitive information that you're creating and manipulating without the help of `cryptopass.util.clj`.    

## License

Copyright © 2018 Dimitrios Piliouras

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
