;; A live handshake WITH Encrypted ClientHello, against a server that serves it.
;;
;;   clojure -M scripts/live_ech.clj [host] [corrupt]
;;
;; The ECHConfigList is fetched from the host's HTTPS resource record over
;; DNS-over-HTTPS, which is where a real client gets it. Nothing is pinned:
;; the point of this script is not the certificate, it is whether a **real
;; server** accepts what this client encrypts -- and the server says so by
;; putting the acceptance confirmation in ServerHello.random.
;;
;; That is the only external evidence available for ECH. The draft is not an
;; RFC and publishes no test vectors, so short of a live server agreeing, every
;; check this repository can run is the two halves of `tls.ech` agreeing with
;; each other.
;;
;; It talks to the public internet and it depends on someone else's deployment,
;; so it is a script and not a test.
(require '[tls.client :as client] '[tls.result :as r]
         '[tls.provider.jvm :as jvm] '[tls.transport.jvm :as tp]
         '[clojure.string :as str])

(defn- doh-ech
  "The `ech=` parameter of the host's HTTPS RR, as bytes."
  [host]
  (let [url (str "https://cloudflare-dns.com/dns-query?name=" host "&type=HTTPS")
        conn (doto (.openConnection (java.net.URL. url))
               (.setRequestProperty "accept" "application/dns-json")
               (.setConnectTimeout 10000)
               (.setReadTimeout 10000))
        body (slurp (.getInputStream conn))
        answers (->> (re-seq #"\"data\":\"([^\"]*)\"" body) (map second))
        ech (some (fn [d]
                    (some #(when (str/starts-with? % "ech=") (subs % 4))
                          (str/split d #"\s+")))
                  answers)]
    (when ech
      (mapv #(bit-and (int %) 0xff)
            (.decode (java.util.Base64/getDecoder) ^String (str/replace ech "\\" ""))))))

(let [[host corrupt?] *command-line-args*
      host (or host "crypto.cloudflare.com")
      cfg0 (doh-ech host)
      ;; The control. A server that "accepts" whatever it is sent would look
      ;; identical to one that decrypted correctly, so the public key is
      ;; flipped by one bit and the server must then FAIL to decrypt and
      ;; reject -- which the client sees as :ech-rejected.
      cfg (if (and corrupt? cfg0)
            (let [i (- (count cfg0) 30)]
              (assoc (vec cfg0) i (bit-xor 1 (nth cfg0 i))))
            cfg0)]
  (when-not cfg
    (println "no ech= in the HTTPS record for" host "-- nothing to test")
    (System/exit 3))
  (println "ECHConfigList from DNS:" (count cfg) "bytes"
           (if corrupt? "(ONE BIT FLIPPED -- the server must reject)" ""))
  (let [provider (jvm/provider)
        t (tp/socket-transport host 443 {:timeout-ms 15000})
        res (client/handshake provider t
                              {:server-name host
                               ;; Not the point of this script; the question is
                               ;; whether the SERVER accepted ECH, and it
                               ;; answers that before Certificate arrives.
                               :insecure-skip-peer-auth true
                               :ech {:config-list cfg}})]
    (cond
      (and corrupt? (r/error? res) (= :ech-rejected (r/reason res)))
      (println "rejected, as it must with a key the server does not hold")

      corrupt?
      (do (println "A CORRUPTED CONFIG WAS ACCEPTED -- THIS IS A BUG:" (pr-str res))
          (System/exit 1))

      (r/error? res)
      (do (println "handshake failed:" (pr-str (r/err res)))
          ;; :ech-rejected is a real answer, not a crash: it means the client
          ;; built a well-formed outer and the server chose not to accept.
          (System/exit (if (= :ech-rejected (r/reason res)) 2 1)))

      :else
      (let [conn (r/val res)]
        (println "handshake ok, and the server ACCEPTED ECH")
        (println "  host              " host)
        (println "  cipher suite      " (:tls/suite conn))
        (println "  chain             " (count (:tls/peer-certificates conn)) "certificates")
        (client/close! conn)))))
