(ns tls.jdk-provider
  "A JDK-backed provider, TEST SCOPE ONLY.

  ## Delete this file

  `src/tls/provider/jvm.clj` is owned by another agent and is the real one.
  This exists so the protocol layers could be verified against RFC 8448 and
  against a live server before that landed, rather than sitting behind it. It
  is under `test/` deliberately: nothing in `src/` refers to it, and it is not
  on the library's classpath for a consumer.

  Everything here is the JDK's, cited where it is not obvious:

  - SHA-256 / SHA-384 -- `MessageDigest` (FIPS 180-4)
  - HMAC -- `Mac` (FIPS 198-1)
  - X25519 -- `KeyAgreement` (RFC 7748). The JCA speaks X25519 only through
    PKCS8/X.509-wrapped key objects and never raw 32-byte scalars, while every
    TLS key_share carries a raw one; the DER prefixes below are the same
    technique `kotoba-lang/noise`'s `noise.provider.jvm` uses.
  - AES-GCM -- `Cipher` (NIST SP 800-38D), 128-bit tag, which is what
    RFC 8446 section 5.2 requires.
  - ChaCha20-Poly1305 -- `Cipher` (RFC 8439)
  - signatures -- `Signature`. RFC 8446 section 4.4.3 requires RSA
    CertificateVerify signatures to be RSASSA-PSS with the salt length equal
    to the digest length, which is why the PSS parameters are spelled out
    rather than left to the provider default."
  (:import (java.security KeyFactory KeyPairGenerator MessageDigest SecureRandom Signature)
           (java.security.spec PKCS8EncodedKeySpec X509EncodedKeySpec
                               MGF1ParameterSpec PSSParameterSpec)
           (javax.crypto Cipher KeyAgreement Mac)
           (javax.crypto.spec GCMParameterSpec IvParameterSpec SecretKeySpec)))

(defn ->ba ^bytes [bs] (byte-array (map unchecked-byte bs)))
(defn ->vec [^bytes ba] (mapv #(bit-and % 0xff) ba))

;; ------------------------------------------------------------------ hashes

(defn- digest [alg bs]
  (->vec (.digest (MessageDigest/getInstance alg) (->ba bs))))

(defn- hmac [alg k m]
  (let [mac (Mac/getInstance alg)]
    (.init mac (SecretKeySpec. (->ba k) alg))
    (->vec (.doFinal mac (->ba m)))))

;; ------------------------------------------------------------------ X25519

(def ^:private pkcs8-x25519
  ;; OneAsymmetricKey, algorithm OID 1.3.101.110 (X25519)
  [0x30 0x2e 0x02 0x01 0x00 0x30 0x05 0x06 0x03 0x2b 0x65 0x6e 0x04 0x22 0x04 0x20])
(def ^:private spki-x25519
  [0x30 0x2a 0x30 0x05 0x06 0x03 0x2b 0x65 0x6e 0x03 0x21 0x00])

(defn- x25519-private [priv]
  (.generatePrivate (KeyFactory/getInstance "X25519")
                    (PKCS8EncodedKeySpec. (->ba (concat pkcs8-x25519 priv)))))

(defn- x25519-public [pub]
  (.generatePublic (KeyFactory/getInstance "X25519")
                   (X509EncodedKeySpec. (->ba (concat spki-x25519 pub)))))

(defn x25519-keypair []
  (let [kp (.generateKeyPair (KeyPairGenerator/getInstance "X25519"))]
    {:private (vec (drop (count pkcs8-x25519) (->vec (.getEncoded (.getPrivate kp)))))
     :public (vec (drop (count spki-x25519) (->vec (.getEncoded (.getPublic kp)))))}))

(defn x25519-dh [priv peer-pub]
  (let [ka (doto (KeyAgreement/getInstance "X25519") (.init (x25519-private priv)))]
    (.doPhase ka (x25519-public peer-pub) true)
    (->vec (.generateSecret ka))))

;; -------------------------------------------------------------------- AEAD

(defn- gcm [key-bits]
  {:seal (fn [k nonce aad pt]
           (let [c (Cipher/getInstance "AES/GCM/NoPadding")]
             (.init c Cipher/ENCRYPT_MODE (SecretKeySpec. (->ba k) "AES")
                    (GCMParameterSpec. 128 (->ba nonce)))
             (when (seq aad) (.updateAAD c (->ba aad)))
             (->vec (.doFinal c (->ba pt)))))
   :open (fn [k nonce aad ct]
           (try
             (let [c (Cipher/getInstance "AES/GCM/NoPadding")]
               (.init c Cipher/DECRYPT_MODE (SecretKeySpec. (->ba k) "AES")
                      (GCMParameterSpec. 128 (->ba nonce)))
               (when (seq aad) (.updateAAD c (->ba aad)))
               [:ok (->vec (.doFinal c (->ba ct)))])
             ;; The contract is a value, never a throw, and never a plaintext
             ;; on failure. `AEADBadTagException` is the only expected one; a
             ;; different exception is still a failure to authenticate and is
             ;; reported as one rather than escaping into the caller.
             (catch javax.crypto.AEADBadTagException _ [:error :tag-mismatch])
             (catch Exception e [:error (keyword (.getSimpleName (class e)))])))
   :key-bits key-bits})

(def ^:private chacha
  {:seal (fn [k nonce aad pt]
           (let [c (Cipher/getInstance "ChaCha20-Poly1305")]
             (.init c Cipher/ENCRYPT_MODE (SecretKeySpec. (->ba k) "ChaCha20")
                    (IvParameterSpec. (->ba nonce)))
             (when (seq aad) (.updateAAD c (->ba aad)))
             (->vec (.doFinal c (->ba pt)))))
   :open (fn [k nonce aad ct]
           (try
             (let [c (Cipher/getInstance "ChaCha20-Poly1305")]
               (.init c Cipher/DECRYPT_MODE (SecretKeySpec. (->ba k) "ChaCha20")
                      (IvParameterSpec. (->ba nonce)))
               (when (seq aad) (.updateAAD c (->ba aad)))
               [:ok (->vec (.doFinal c (->ba ct)))])
             (catch javax.crypto.AEADBadTagException _ [:error :tag-mismatch])
             (catch Exception e [:error (keyword (.getSimpleName (class e)))])))})

;; -------------------------------------------------------------- signatures

(def signature-algorithms
  "scheme -> [KeyFactory algorithm, Signature algorithm, PSS parameters].

   RFC 8446 section 4.4.3: an RSA CertificateVerify in TLS 1.3 is RSASSA-PSS
   with MGF1 and a salt length equal to the digest length. `rsa_pkcs1_*` is
   deliberately absent -- section 4.4.3 forbids it in CertificateVerify, and
   accepting one is a downgrade to a signature scheme with a much longer
   history of implementation flaws."
  {:ecdsa_secp256r1_sha256 ["EC" "SHA256withECDSA" nil]
   :ecdsa_secp384r1_sha384 ["EC" "SHA384withECDSA" nil]
   :ecdsa_secp521r1_sha512 ["EC" "SHA512withECDSA" nil]
   :ed25519 ["Ed25519" "Ed25519" nil]
   :rsa_pss_rsae_sha256 ["RSA" "RSASSA-PSS" ["SHA-256" MGF1ParameterSpec/SHA256 32]]
   :rsa_pss_rsae_sha384 ["RSA" "RSASSA-PSS" ["SHA-384" MGF1ParameterSpec/SHA384 48]]
   :rsa_pss_rsae_sha512 ["RSA" "RSASSA-PSS" ["SHA-512" MGF1ParameterSpec/SHA512 64]]
   :rsa_pss_pss_sha256 ["RSASSA-PSS" "RSASSA-PSS" ["SHA-256" MGF1ParameterSpec/SHA256 32]]
   :rsa_pss_pss_sha384 ["RSASSA-PSS" "RSASSA-PSS" ["SHA-384" MGF1ParameterSpec/SHA384 48]]
   :rsa_pss_pss_sha512 ["RSASSA-PSS" "RSASSA-PSS" ["SHA-512" MGF1ParameterSpec/SHA512 64]]})

(defn verify-signature
  "-> [:ok true] | [:error reason]. Never throws, never returns true for a
   scheme it does not know: an unknown scheme is a refusal, because the
   alternative is authenticating a peer with a signature nobody checked."
  [scheme spki-der message signature]
  (if-let [[key-alg sig-alg pss] (get signature-algorithms scheme)]
    (try
      (let [pk (.generatePublic (KeyFactory/getInstance key-alg)
                                (X509EncodedKeySpec. (->ba spki-der)))
            s (Signature/getInstance sig-alg)]
        (when pss
          (let [[md mgf salt] pss]
            (.setParameter s (PSSParameterSpec. md "MGF1" mgf (int salt) (int 1)))))
        (.initVerify s pk)
        (.update s (->ba message))
        (if (.verify s (->ba signature))
          [:ok true]
          [:error :signature-invalid]))
      (catch Exception e [:error (keyword (str "verify-" (.getSimpleName (class e))))]))
    [:error :unsupported-signature-scheme]))

;; ----------------------------------------------------------------- provider

(def ^:private rng (SecureRandom.))

(def provider
  {:hash {:sha256 (partial digest "SHA-256")
          :sha384 (partial digest "SHA-384")}
   :hmac (fn [hash-kw k m]
           (hmac (case hash-kw :sha256 "HmacSHA256" :sha384 "HmacSHA384") k m))
   :x25519 {:keypair x25519-keypair :dh x25519-dh}
   :aead {:aes-128-gcm (gcm 128)
          :aes-256-gcm (gcm 256)
          :chacha20-poly1305 chacha}
   :signature {:verify verify-signature}
   :random (fn [n] (let [b (byte-array n)] (.nextBytes rng b) (->vec b)))})
