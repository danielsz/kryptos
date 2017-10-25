(set-env!
 :source-paths   #{"src"}
 :resource-paths #{"src"}
 :dependencies '[[digest "1.4.6"]
                 [pandect "0.6.1"]
                 [org.bouncycastle/bcprov-jdk15on "1.58"]])

(task-options!
 push {:repo-map {:url "https://clojars.org/repo/"}}
 pom {:project 'org.danielsz/kryptos
      :version "0.1.0-SNAPSHOT"
      :scm {:name "git"
            :url "https://github.com/danielsz/kryptos"}})

(deftask build
  []
  (comp (pom) (jar) (install)))

(deftask push-release
  []
  (comp
   (build)
   (push)))
