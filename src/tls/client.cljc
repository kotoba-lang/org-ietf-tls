(ns tls.client
  "A TLS 1.3 client: full 1-RTT handshake, then application data.

  Pure, in the sense that matters: this namespace opens no socket and reads no
  clock. It is driven by a `transport` map of two functions,

      {:send (fn [bytes] ...)   ; write bytes, return anything
       :recv (fn [] bytes)}     ; block for at least one byte, [] on EOF

  and a `provider` supplying the cryptography. `tls.transport.jvm` is one
  implementation of the former; a WASM host or aiueos would be another.

  ## What this client does not do

  Said plainly, because a TLS client that quietly skips a check is worse than
  no TLS client:

  - **No trust-anchor chain validation.** Peer authentication is by SPKI pin
    (`:pin-spki-sha256`) or, if the caller explicitly passes
    `:insecure-skip-peer-auth`, not at all. There is no root store here, no
    name constraints, no CRL, no OCSP. `tls.cert` (another agent's file) is
    where that will live.
  - **No HelloRetryRequest.** One key share, X25519, and a refusal naming the
    group the server asked for if it wants another.
  - **No resumption, no 0-RTT, no PSK, no client certificates.**
  - **No KeyUpdate.** A `key_update` from the peer is a refusal, not a
    silently-ignored message: ignoring it desynchronises the keys and the next
    record fails with no explanation.
  - **No record-boundary reassembly of a handshake message across a *key
    change*.** Messages are reassembled across records within one flight,
    which is what real servers need; a message split across the
    ServerHello/EncryptedExtensions key boundary cannot legally occur.

  ## What it does check

  Every one of these has a negative test:

  - the ServerHello is TLS 1.3 by `supported_versions`, not by
    `legacy_version` (section 4.1.3)
  - `legacy_session_id_echo` matches what was sent
  - the cipher suite and key-share group were both offered
  - the server's `CertificateVerify` signature is over the section 4.4.3
    context string and the transcript, and verifies against the leaf's SPKI
  - the server's `Finished` verifies against the handshake traffic secret
  - the peer's SPKI matches the pin, when one is given"
  (:require [tls.alert :as alert]
            [tls.codec :as c]
            [tls.extension :as ext]
            [tls.handshake :as hs]
            [tls.record :as rec]
            [tls.result :as r :refer [ok error]]
            [tls.schedule :as sch]
            [tls.suite :as suite]
            [tls.transcript :as tr]))

;; ------------------------------------------------------------ record I/O

(defn- reader
  "A buffered record reader over `:recv`. Records arrive split across TCP
   segments; a client that assumes one `recv` is one record works on a fast
   loopback and fails on the internet."
  [transport]
  (atom {:buffer [] :transport transport :eof false}))

(defn- fill! [st]
  (let [chunk (vec ((get-in @st [:transport :recv])))]
    (if (empty? chunk)
      (do (swap! st assoc :eof true) false)
      (do (swap! st update :buffer into chunk) true))))

(defn- next-record!
  "One complete record, or an error. Reads until the header says how long the
   body is and then until the body is whole."
  [st]
  (loop []
    (let [b (:buffer @st)]
      (if (< (count b) 5)
        (if (:eof @st)
          (error :internal_error :connection-closed {:tls/stage :record-header})
          (do (fill! st) (recur)))
        (let [n (+ (* 256 (nth b 3)) (nth b 4))
              limit rec/max-ciphertext]
          (cond
            (> n limit) (error :record_overflow :record-too-long {:tls/length n :tls/max limit})
            (< (count b) (+ 5 n))
            (if (:eof @st)
              (error :internal_error :connection-closed {:tls/stage :record-body})
              (do (fill! st) (recur)))
            :else
            (let [record (subvec b 0 (+ 5 n))]
              (swap! st assoc :buffer (subvec b (+ 5 n)))
              (ok record))))))))

(defn- send! [transport bytes] ((:send transport) (vec bytes)))

;; ------------------------------------------------------- handshake reader

(defn- handshake-stream
  "Protected handshake messages, reassembled across records.

  `change_cipher_spec` records are skipped, not processed: section 5 makes
  them meaningless in TLS 1.3 and D.4 says a client MUST ignore them. Real
  servers send one, and a client that treats it as an unexpected message
  cannot talk to them."
  [st suite keys]
  (atom {:st st :suite suite :keys keys :seq 0 :pending [] :queue []}))

(defn- pump!
  "Read one record and append any handshake messages it yields."
  [hstream]
  (let [{:keys [st suite keys]} @hstream]
    (r/let-ok [record (next-record! st)]
      (let [t (first record)]
        (cond
          (= t (get rec/content-types :change_cipher_spec)) (ok :skipped)
          :else
          (r/let-ok [opened (rec/open suite keys (:seq @hstream) record)]
            (do (swap! hstream update :seq inc)
                (case (:tls/content-type opened)
                  :handshake
                  (let [buf (into (:pending @hstream) (:tls/content opened))]
                    (loop [b buf, msgs []]
                      (if (< (count b) 4)
                        (do (swap! hstream assoc :pending b)
                            (swap! hstream update :queue into msgs)
                            (ok :ok))
                        (let [n (+ (* 65536 (nth b 1)) (* 256 (nth b 2)) (nth b 3))]
                          (if (< (count b) (+ 4 n))
                            (do (swap! hstream assoc :pending b)
                                (swap! hstream update :queue into msgs)
                                (ok :ok))
                            (recur (subvec b (+ 4 n)) (conj msgs (subvec b 0 (+ 4 n)))))))))
                  :alert
                  (let [[level desc] (:tls/content opened)]
                    (error :handshake_failure :peer-alert
                           {:tls/level level
                            :tls/description (alert/describe desc)
                            :tls/code desc}))
                  (error :unexpected_message :unexpected-content-type
                         {:tls/content-type (:tls/content-type opened)})))))))))

(defn- next-handshake!
  "The next complete handshake message, pumping records as needed."
  [hstream]
  (loop [guard 0]
    (if (seq (:queue @hstream))
      (let [m (first (:queue @hstream))]
        (swap! hstream update :queue rest)
        (ok (vec m)))
      (if (> guard 4096)
        (error :internal_error :handshake-stream-stalled {})
        (r/let-ok [_ (pump! hstream)] (recur (inc guard)))))))

;; --------------------------------------------------------------- handshake

(def default-signature-algorithms
  "Offered in the ClientHello. `rsa_pkcs1_*` is present because RFC 8446
   section 4.2.3 allows it for *certificate* signatures even though section
   4.4.3 forbids it in CertificateVerify -- omitting it makes some real chains
   unusable. `tls.cert` is responsible for enforcing the CertificateVerify
   restriction; this list is what we are willing to see."
  [:ecdsa_secp256r1_sha256 :ecdsa_secp384r1_sha384
   :rsa_pss_rsae_sha256 :rsa_pss_rsae_sha384 :rsa_pss_rsae_sha512
   :ed25519
   :rsa_pkcs1_sha256 :rsa_pkcs1_sha384])

(defn- build-client-hello [provider {:keys [server-name suites signature-algorithms]} share]
  (r/let-ok [sni (ext/server-name server-name)
             sv (ext/supported-versions-client)
             gr (ext/supported-groups [:x25519])
             sa (ext/signature-algorithms (or signature-algorithms default-signature-algorithms))
             ks (ext/key-share-client [[:x25519 (:public share)]])
             modes (ext/psk-key-exchange-modes [:psk_dhe_ke])]
    (let [random ((:random provider) 32)
          session-id ((:random provider) 32)]
      (r/let-ok [msg (hs/client-hello
                      {:random random
                       :session-id session-id
                       :cipher-suites (mapv #(get suite/ids %) suites)
                       :extensions [(ext/->ext :server_name sni)
                                    (ext/->ext :supported_groups gr)
                                    (ext/->ext :signature_algorithms sa)
                                    (ext/->ext :supported_versions sv)
                                    (ext/->ext :psk_key_exchange_modes modes)
                                    (ext/->ext :key_share ks)]})]
        (ok {:tls/message msg :tls/session-id session-id})))))

(defn- authenticate-peer
  "Peer authentication, stated as one function so that what it does and does
   not do is inspectable in one place.

   With `:pin-spki-sha256`, the leaf's SubjectPublicKeyInfo must hash to the
   pin. That is a *stronger* statement than chain validation for a known host
   and a much weaker one for an unknown host, and the difference is the
   caller's to make -- so there is no default, and no silent success:
   `authenticate-peer` refuses unless one of the two options was passed."
  [provider config leaf-der spki-der]
  (let [{:keys [pin-spki-sha256 insecure-skip-peer-auth verify-chain]} config]
    (cond
      (fn? verify-chain) (verify-chain leaf-der spki-der)
      (some? pin-spki-sha256)
      (let [got (c/hex ((get-in provider [:hash :sha256]) (vec spki-der)))]
        (if (= (clojure.string/lower-case pin-spki-sha256) got)
          (ok {:tls/authenticated-by :spki-pin :tls/spki-sha256 got})
          (error :bad_certificate :spki-pin-mismatch
                 {:tls/expected pin-spki-sha256 :tls/actual got})))
      insecure-skip-peer-auth
      (ok {:tls/authenticated-by :none
           :tls/warning "peer identity was not checked"})
      :else
      ;; The important refusal in this file. A TLS client with no configured
      ;; way to authenticate its peer has not got a weaker connection -- it has
      ;; an unauthenticated one, and returning success here is how that becomes
      ;; invisible.
      (error :certificate_required :no-peer-authentication-configured
             {:tls/note "pass :pin-spki-sha256, :verify-chain, or :insecure-skip-peer-auth"}))))

(defn- spki-of
  "The SubjectPublicKeyInfo of a DER certificate, as bytes.

   Extracted structurally rather than parsed: a Certificate is
   `SEQUENCE { tbsCertificate SEQUENCE {...}, ... }` and the SPKI is the first
   child of tbsCertificate whose tag is SEQUENCE and which parses as
   `{AlgorithmIdentifier, BIT STRING}`. Doing it by hand here is a stopgap --
   `tls.cert` owns this properly, on top of `org-ietf-x509`. It is marked so
   because a hand-rolled DER walk is exactly the kind of code that should not
   quietly become permanent."
  [der]
  (letfn [(tlv [b i]
            (when (< (inc i) (count b))
              (let [tag (nth b i)
                    l0 (nth b (inc i))]
                (if (< l0 0x80)
                  {:tag tag :hstart i :vstart (+ i 2) :len l0 :end (+ i 2 l0)}
                  (let [nb (- l0 0x80)
                        len (reduce (fn [a k] (+ (* a 256) (nth b (+ i 2 k)))) 0 (range nb))]
                    {:tag tag :hstart i :vstart (+ i 2 nb) :len len :end (+ i 2 nb len)})))))
          (children [b start end]
            (loop [i start acc []]
              (if (>= i end) acc
                  (let [t (tlv b i)] (if (nil? t) acc (recur (:end t) (conj acc t)))))))]
    (let [b (vec der)
          cert (tlv b 0)
          tbs (first (children b (:vstart cert) (:end cert)))
          kids (children b (:vstart tbs) (:end tbs))
          ;; SPKI is the SEQUENCE whose two children are a SEQUENCE and a BIT STRING
          spki (first (filter (fn [t]
                                (and (= 0x30 (:tag t))
                                     (let [cs (children b (:vstart t) (:end t))]
                                       (and (= 2 (count cs))
                                            (= 0x30 (:tag (first cs)))
                                            (= 0x03 (:tag (second cs)))))))
                              kids))]
      (if spki
        (ok (subvec b (:hstart spki) (:end spki)))
        (error :bad_certificate :spki-not-found {})))))

(defn handshake
  "Run the 1-RTT handshake. Returns a connection value or an error.

     (handshake provider transport
                {:server-name \"kotobase.net\"
                 :pin-spki-sha256 \"5060...\"})"
  [provider transport config]
  (let [suites (or (:suites config) (suite/negotiable provider))]
    (if (empty? suites)
      (error :insufficient_security :provider-supports-no-suite {})
      (r/let-ok [share (ok ((get-in provider [:x25519 :keypair])))
                 ch (build-client-hello provider (assoc config :suites suites) share)]
        (let [ch-msg (:tls/message ch)]
          (r/let-ok [ch-record (rec/plaintext-record :handshake ch-msg)]
            (do
              (send! transport ch-record)
              (let [st (reader transport)]
                (r/let-ok [sh-record (next-record! st)]
                  (cond
                    (= (first sh-record) (get rec/content-types :alert))
                    (error :handshake_failure :peer-alert-before-server-hello
                           {:tls/description (alert/describe (second (drop 5 sh-record)))})
                    (not= (first sh-record) (get rec/content-types :handshake))
                    (error :unexpected_message :expected-server-hello
                           {:tls/content-type (first sh-record)})
                    :else
                    (r/let-ok [parsed (rec/parse-record sh-record)
                               sh-msg (hs/split (:tls/fragment parsed))
                               sh (hs/parse-server-hello (:tls/body sh-msg))
                               neg (hs/check-server-hello
                                    sh {:session-id (:tls/session-id ch)
                                        :offered-suites (mapv #(get suite/ids %) suites)
                                        :offered-groups [:x25519]})
                               suite-name (ok (get suite/by-id (:tls/cipher-suite neg)))
                               ste (suite/suite provider suite-name)
                               h (sch/hashes provider (:hash ste))]
                      (let [dhe ((get-in provider [:x25519 :dh])
                                 (:private share) (:tls/peer-key-share neg))
                            t0 (-> (tr/transcript) (tr/add ch-msg) (tr/add (:tls/raw sh-msg)))
                            th (tr/digest t0 (:hash h))
                            early (sch/early-secret h)]
                        (r/let-ok [hs-secret (sch/handshake-secret h early dhe)
                                   c-hs (sch/derive-secret h hs-secret "c hs traffic" th)
                                   s-hs (sch/derive-secret h hs-secret "s hs traffic" th)
                                   s-keys (sch/traffic-keys h s-hs ste)
                                   c-keys (sch/traffic-keys h c-hs ste)]
                          (let [hstream (handshake-stream st ste s-keys)]
                            ;; ---- server flight -------------------------------
                            (r/let-ok [ee (next-handshake! hstream)
                                       ee-m (hs/split ee)]
                              (let []
                                (if (not= :encrypted_extensions (:tls/type ee-m))
                                  (error :unexpected_message :expected-encrypted-extensions
                                         {:tls/type (:tls/type ee-m)})
                                  (r/let-ok [_ (hs/parse-encrypted-extensions (:tls/body ee-m))
                                             cert-raw (next-handshake! hstream)
                                             cert-m (hs/split cert-raw)]
                                    (let []
                                      (if (not= :certificate (:tls/type cert-m))
                                        (error :unexpected_message :expected-certificate
                                               {:tls/type (:tls/type cert-m)
                                                :tls/note "this client does not do PSK, so a server that skips Certificate is out of contract"})
                                        (r/let-ok [cert (hs/parse-certificate (:tls/body cert-m))
                                                   leaf (ok (first (:tls/certificates cert)))
                                                   spki (spki-of leaf)
                                                   auth (authenticate-peer provider config leaf spki)
                                                   cv-raw (next-handshake! hstream)
                                                   cv-m (hs/split cv-raw)]
                                          (let [t-cert (-> t0 (tr/add ee) (tr/add cert-raw))]
                                            (if (not= :certificate_verify (:tls/type cv-m))
                                              (error :unexpected_message :expected-certificate-verify
                                                     {:tls/type (:tls/type cv-m)})
                                              (r/let-ok [cv (hs/parse-certificate-verify (:tls/body cv-m))]
                                                (let [content (hs/certificate-verify-content
                                                               :server (tr/digest t-cert (:hash h)))
                                                      vres ((get-in provider [:signature :verify])
                                                            (:tls/scheme cv) spki content (:tls/signature cv))]
                                                  (if-not (and (vector? vres) (= :ok (first vres)) (true? (second vres)))
                                                    (error :decrypt_error :certificate-verify-failed
                                                           {:tls/scheme (:tls/scheme cv)
                                                            :tls/provider-said (if (vector? vres) (second vres) vres)})
                                                    (r/let-ok [fin-raw (next-handshake! hstream)
                                                               fin-m (hs/split fin-raw)]
                                                      (let [t-cv (tr/add t-cert cv-raw)]
                                                        (if (not= :finished (:tls/type fin-m))
                                                          (error :unexpected_message :expected-finished
                                                                 {:tls/type (:tls/type fin-m)})
                                                          (r/let-ok [_ (sch/check-finished
                                                                        h s-hs (tr/digest t-cv (:hash h))
                                                                        (:tls/body fin-m))
                                                                     ;; ---- our Finished -------------
                                                                     master (sch/master-secret h hs-secret)
                                                                     t-sfin (ok (tr/add t-cv fin-raw))
                                                                     sfin-hash (ok (tr/digest t-sfin (:hash h)))
                                                                     c-ap (sch/derive-secret h master "c ap traffic" sfin-hash)
                                                                     s-ap (sch/derive-secret h master "s ap traffic" sfin-hash)
                                                                     vd (sch/verify-data h c-hs sfin-hash)
                                                                     my-fin (hs/finished vd)
                                                                     ccs (rec/plaintext-record :change_cipher_spec [1])
                                                                     fin-record (rec/seal ste c-keys 0 :handshake my-fin)
                                                                     c-ap-keys (sch/traffic-keys h c-ap ste)
                                                                     s-ap-keys (sch/traffic-keys h s-ap ste)]
                                                            (do
                                                              ;; middlebox compatibility, RFC 8446 appendix D.4
                                                              (send! transport ccs)
                                                              (send! transport fin-record)
                                                              (ok {:tls/suite (:tls/suite ste)
                                                                   :tls/suite-value ste
                                                                   :tls/hash h
                                                                   :tls/reader st
                                                                   :tls/transport transport
                                                                   :tls/peer-certificates (:tls/certificates cert)
                                                                   :tls/peer-spki spki
                                                                   :tls/authentication auth
                                                                   :tls/certificate-verify-scheme (:tls/scheme cv)
                                                                   :tls/write {:keys c-ap-keys :seq (atom 0)}
                                                                   :tls/read {:keys s-ap-keys :seq (atom 0)}
                                                                   :tls/exporter-master
                                                                   (r/val (sch/derive-secret h master "exp master" sfin-hash))
                                                                   :tls/resumption-master nil}))))))))))))))))))))))))))))))))

;; --------------------------------------------------------- application data

(defn write!
  "Send application data as one or more records, respecting the 2^14 limit."
  [conn bytes]
  (let [ste (:tls/suite-value conn)
        {:keys [keys seq]} (:tls/write conn)]
    (loop [b (vec bytes)]
      (if (empty? b)
        (ok (count bytes))
        (let [chunk (subvec b 0 (min (count b) rec/max-plaintext))
              res (rec/seal ste keys @seq :application_data chunk)]
          (if (r/error? res)
            res
            (do (send! (:tls/transport conn) (r/val res))
                (swap! seq inc)
                (recur (subvec b (count chunk))))))))))

(defn read!
  "Read the next application-data record.

   -> `[:ok {:tls/content bytes}]`, `[:ok {:tls/closed true}]` on close_notify,
   or an error. A `new_session_ticket` is consumed and skipped (real servers
   send them immediately after the handshake); a `key_update` is a refusal,
   because ignoring one desynchronises the keys silently."
  [conn]
  (let [ste (:tls/suite-value conn)
        st (:tls/reader conn)
        {:keys [keys seq]} (:tls/read conn)]
    (loop [guard 0]
      (if (> guard 64)
        (error :internal_error :too-many-non-data-records {})
        (r/let-ok [record (next-record! st)]
          (if (= (first record) (get rec/content-types :change_cipher_spec))
            (recur (inc guard))
            (r/let-ok [opened (rec/open ste keys @seq record)]
              (do
                (swap! seq inc)
                (case (:tls/content-type opened)
                  :application_data (ok {:tls/content (:tls/content opened)})
                  :alert (let [[level desc] (:tls/content opened)
                               d (alert/describe desc)]
                           (if (= :close_notify d)
                             (ok {:tls/closed true})
                             (error :handshake_failure :peer-alert
                                    {:tls/level level :tls/description d :tls/code desc})))
                  :handshake
                  (r/let-ok [msgs (hs/split-all (:tls/content opened))]
                    (let [types (set (map :tls/type msgs))]
                      (cond
                        (contains? types :key_update)
                        (error :unexpected_message :key-update-not-implemented
                               {:tls/note "ignoring a KeyUpdate desynchronises the keys silently, so this refuses"})
                        :else (recur (inc guard)))))
                  (error :unexpected_message :unexpected-content-type
                         {:tls/content-type (:tls/content-type opened)}))))))))))

(defn close!
  "Send a `close_notify` (section 6.1) and stop. Not doing this is how a peer
   cannot distinguish an orderly shutdown from a truncation attack."
  [conn]
  (let [ste (:tls/suite-value conn)
        {:keys [keys seq]} (:tls/write conn)
        res (rec/seal ste keys @seq :alert (alert/encode :close_notify :warning))]
    (when (r/ok? res) (send! (:tls/transport conn) (r/val res)) (swap! seq inc))
    (ok true)))
