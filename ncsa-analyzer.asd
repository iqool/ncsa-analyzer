;;;; ncsa-analyzer.asd

(asdf:defsystem #:ncsa-analyzer
  :description "Query-System for Logfile Analyzation"
  :author "Your Name <patrick.krusenotto@gmail.com>"
  :license  "Specify license here"
  :version "0.0.1"
  :serial t
  :depends-on (#:alexandria
	       #:cl-ppcre
	       #:lazy-memo)
  :components ((:file "package")
               (:file "ncsa-analyzer")))
