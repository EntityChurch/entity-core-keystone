;;;; varint.lisp — multicodec-style unsigned LEB128 varints (V7 §1.5 / §7.3).
;;;;
;;;; Invariant N1: route every format-code / key-type / hash-type prefix through a
;;;; REAL varint primitive, not fixed bytes. Currently-allocated codes are all
;;;; < 0x80 (single byte), but a code >= 0x80 MUST extend correctly (e.g. 128 ->
;;;; 0x80 0x01). CL integers are native bignums, so the value carrier has no width
;;;; trap.

(in-package #:entity-core)

(deftype octet () '(unsigned-byte 8))
(deftype octet-vector () '(simple-array (unsigned-byte 8) (*)))

(declaim (inline make-octet-vector))
(defun make-octet-vector (n)
  (make-array n :element-type '(unsigned-byte 8)))

(defun varint-encode (n)
  "Encode a non-negative integer N as an unsigned LEB128 octet-vector."
  (check-type n (integer 0))
  (let ((out (make-array 0 :element-type '(unsigned-byte 8)
                           :adjustable t :fill-pointer 0)))
    (loop
      (let ((b (logand n #x7f)))
        (setf n (ash n -7))
        (if (zerop n)
            (progn (vector-push-extend b out) (return))
            (vector-push-extend (logior b #x80) out))))
    (coerce out 'octet-vector)))

(defun varint-decode (octets &optional (start 0))
  "Decode an unsigned LEB128 varint from OCTETS at START.
Returns (values value next-index). Signals TRUNCATED-INPUT if it runs off the end."
  (let ((value 0) (shift 0) (i start) (len (length octets)))
    (loop
      (when (>= i len)
        (error 'truncated-input :detail :varint))
      (let ((b (aref octets i)))
        (incf i)
        (setf value (logior value (ash (logand b #x7f) shift)))
        (when (zerop (logand b #x80))
          (return (values value i)))
        (incf shift 7)))))
