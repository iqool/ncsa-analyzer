;;;; ncsa-analyzer.lisp

(in-package #:ncsa-analyzer)

(defparameter *test-log-line*
  "180.76.15.5 - - [23/Jan/2017:01:23:45 +0100] \"GET /cda/fragment/relatedcontent/10406/19112659?keywords=Fukushima%2CJapan%2Ccore+meltdown%2Ctsunami%2Cresettlement%2Cdecontamination&title=Fukushima+five+years+on& HTTP/1.1\" 200 950")

(defparameter *t2* "66.249.72.225 - - [28/Sep/2007:15:51:37 +0200] \"GET / HTTP/1.1\" 304 - \"-\" \"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)\"")

(defmacro ! (function &rest arguments)
  `(funcall ,function ,@arguments))

(defmacro !* (function &rest arguments)
  `(multiple-value-call ,function ,@arguments))

(defmacro !! (function &rest arguments)
  `(apply ,function ,@arguments))

(defun day-of-week (day month year)
  "Returns the day of the week as an integer.
Sunday is 0. Works for years after 1752."
  (let ((offset '(0 3 2 5 0 3 5 1 4 6 2 4)))
    (when (< month 3)
      (decf year 1))
    (mod
     (truncate (+ year
                  (/ year 4)
                  (/ (- year)
                     100)
                  (/ year 400)
                  (nth (1- month) offset)
                  day
                  -1))
     7)))

(defun month-number (month)
  "computes the month index from a month tag"
  (1+ (position
       month
       '("Jan" "Feb" "Mar" "Apr" "May" "Jun"
	 "Jul" "Aug" "Sep" "Oct" "Nov" "Dec")
       :test #'string=)))

(defun rational-time-zone (tz)
  (* (ecase (aref tz 0) (#\- -1) (#\+ +1))
     (+ (parse-integer tz :start 1 :end 3)
        (/ (parse-integer tz :start 3 :end 5) 60))))

(defun numberify-time-date (day month year hour min sec time-zone)
  "takes time stamp components as strings and returns
integer values"
  (let ((iday   (parse-integer day))
	(imonth (month-number  month))
	(iyear  (parse-integer year)))
    (values
     (parse-integer sec)
     (parse-integer min)
     (parse-integer hour)
     iday
     imonth
     iyear
     (- (rational-time-zone time-zone)))))

(defun decoded-time-from-ncsa-date-and-time-zone (time-stamp time-zone)
  ;;; "23/Jan/2017:00:00:00 +0000"
  (cl-ppcre:register-groups-bind (day month year hour min sec)
      ("(\\d+)/([A-Z][a-z]{2})/(\\d{4}):(\\d{2}):(\\d{2}):(\\d{2})" time-stamp)
    (numberify-time-date day month year hour min sec time-zone)))

(defun epoch-from-ncsa-date (date time-zone)
  "takes an nsca-style date and timezone and returns a unix time stamp"
  (multiple-value-call
      #'encode-universal-time
    (decoded-time-from-ncsa-date-and-time-zone date time-zone)))

(defun parse-ncsa-combined-line-with-promises (l)
  (destructuring-bind (ip-raw ident user time-raw zone-raw method url protocol status size referer &rest user-agent-raw)
      (cl-ppcre:split "\\s+" l)
    (let ((time (subseq time-raw 1))
	  (zone (subseq zone-raw 0 5)))
      (vector
       (promise (mapcar #'parse-integer (cl-ppcre:split "\\." ip-raw)))
       ip-raw
       ident
       user
       (promise (epoch-from-ncsa-date time zone))
       time
       zone
       (subseq method 1)
       url
       protocol
       status
       size
       referer
       (promise (apply #'concatenate 'string user-agent-raw))
       user-agent-raw
       ))))

(defun parse-ncsa-combined-line (l)
  (destructuring-bind (ip-raw ident user time-raw zone-raw method url protocol status size referer &rest user-agent-raw)
      (cl-ppcre:split "\\s+" l)
    (let ((time (subseq time-raw 1))
	  (zone (subseq zone-raw 0 5)))
      (vector
       (mapcar #'parse-integer (cl-ppcre:split "\\." ip-raw))
       ip-raw
       ident
       user
       (epoch-from-ncsa-date time zone)
       time
       zone
       (subseq method 1)
       url
       protocol
       status
       size
       referer
       (apply #'concatenate 'string user-agent-raw)
       user-agent-raw
       ))))

(defun parse-ncsa-combined-line-to-plist (l)
  (destructuring-bind (ip-raw ident user time-raw zone-raw method url protocol status size referer &rest user-agent-raw)
      (cl-ppcre:split "\\s+" l)
    (let ((time (subseq time-raw 1))
	  (zone (subseq zone-raw 0 5)))
      (list
       :ip (mapcar #'parse-integer (cl-ppcre:split "\\." ip-raw))
       :ip-raw ip-raw
       :ident ident
       :user user
       :epoch (epoch-from-ncsa-date time zone)
       :timestamp time
       :zone zone
       :method (subseq method 1)
       :url url
       :protocol protocol
       :status status
       :size size
       :referer referer
       :user-agent (apply #'concatenate 'string user-agent-raw)
       :user-agent-raw user-agent-raw
       ))))

(defun textfile (name)
  (let (;(eof (gensym))
	(s (open name)))
    (lambda ()
      (read-line s nil nil))))

(defun dump (src)
  (let ((textline (funcall src)))
    (when textline
      (print textline)
      (dump src))))

(defun file (name)
  (let ((src (textfile name)))
    (labels ((file-iterator ()
	       (let ((textline (funcall src)))
		 (print textline)
		 (if textline
		     (parse-ncsa-combined-line-to-plist textline)))))
      #'file-iterator)))

  
(defun test() (dump (file "access.small.log")))
