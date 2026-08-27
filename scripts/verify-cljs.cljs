#!/usr/bin/env nbb
;; Run `tls.ech-test` on the ClojureScript side.
;;
;; Only that namespace. The rest of this suite depends on the JVM provider,
;; and a runner that quietly found nothing to run would report success -- so
;; the one namespace is named, and the count is asserted below.
;;
;;   nbb --classpath "$(clojure -A:cljs -Spath)" scripts/verify-cljs.cljs
(ns verify-cljs
  (:require [clojure.test :as t]
            [tls.ech-test]))

(defmethod t/report [:cljs.test/default :end-run-tests] [m]
  (println)
  (cond
    (zero? (+ (:pass m) (:fail m) (:error m)))
    (do (println "REFUSING: the runner executed no assertions")
        (js/process.exit 2))

    (t/successful? m)
    (println "all checks passed on the ClojureScript path")

    :else
    (do (println "FAILED on the ClojureScript path")
        (js/process.exit 1))))

(t/run-tests 'tls.ech-test)
