;;;; ncsa-analyzer.lisp

(in-package #:ncsa-analyzer)

(defparameter *test-log-line*
  "180.76.15.5 - - [23/Jan/2017:01:23:45 +0100] \"GET /cda/fragment/relatedcontent/10406/19112659?keywords=Fukushima%2CJapan%2Ccore+meltdown%2Ctsunami%2Cresettlement%2Cdecontamination&title=Fukushima+five+years+on& HTTP/1.1\" 200 950")

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
  (* (ecase (aref tz 0) (#\- +1) (#\+ -1))
     (+ (parse-integer tz :start 1 :end 3)
        (/ (parse-integer tz :start 3 :end 5) 60))))

(defun numberify (day month year hour min sec time-zone)
  "takes time stamp components as strings and returns
integer values"
  (let ((iday   (parse-integer day))
	(imonth (month-number  month))
	(iyear  (parse-integer year))
        ;; (daylight-savings-time nil)
	)
    (values
     (parse-integer sec)
     (parse-integer min)
     (parse-integer hour)
     iday
     imonth
     iyear
;;;     (day-of-week iday imonth iyear)
;;;     daylight-savings-time
     (rational-time-zone time-zone))))

(defun decoded-time-from-ncsa-date-and-time-zone (time-stamp time-zone)
  ;;; "23/Jan/2017:00:00:00 +0000"
  (cl-ppcre:register-groups-bind (day month year hour min sec)
      ("(\\d+)/([A-Z][a-z]{2})/(\\d{4}):(\\d{2}):(\\d{2}):(\\d{2})" time-stamp)
    (numberify day month year hour min sec time-zone)))

(defun epoch-from-ncsa-date (date time-zone)
  "takes an nsca-style date and timezone and returns a unix time stamp"
  (multiple-value-call
      #'encode-universal-time
    (decoded-time-from-ncsa-date-and-time-zone date time-zone)))

(defmacro delay (expr)
  `(lambda () ,expr))

(defun parse-ncsa-line (l)
  (destructuring-bind (ip ident user time zone method url protocol status size)
      (cl-ppcre:split "\\s+" l)
    (values
     (delay (mapcar #'parse-integer
                    (cl-ppcre:all-matches-as-strings "\\d+" ip)))
     ident
     user
     (subseq time 1)
     (subseq zone 0 5)
     (subseq method 1)
     url
     (subseq protocol 0 (1- (length protocol)))
     (parse-integer status)
     (parse-integer size))))

(defun lazy (closure)
  (let ((calculated-p)
        (result))
    (lambda ()
      (if calculated-p 
          result
          (prog1
              (setq result (funcall closure))
            (setq calculated-p t))))))
