;;;; ncsa-analyzer.asd

(asdf:defsystem #:ncsa-analyzer
  :description "query system for analyzation of ncsa logfiles"
  :author "Patrick M. Krusenotto<patrick.krusenotto@gmail.com>"
  :license  "Specify license here"
  :version "0.0.1"
  :serial t
  :depends-on (#:alexandria #:cl-ppcre)
  :components ((:file "package")
               (:file "ncsa-analyzer")))
