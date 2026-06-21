;;;; base58.lisp — Base58 (Bitcoin alphabet) encode/decode, hand-rolled.
;;;;
;;;; Used for peer-id formatting/parsing (V7 §1.2 / §7.3). Leading zero bytes map
;;;; to a leading "1" each, per the standard Base58 convention (leading-zero
;;;; preserving on both directions).

(in-package #:entity-core)

(defparameter +base58-alphabet+
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  "Bitcoin Base58 alphabet (no 0, O, I, l).")

(defun %octets->integer (octets)
  "Big-endian octet-vector -> non-negative integer."
  (let ((n 0))
    (loop for b across octets do (setf n (+ (ash n 8) b)))
    n))

(defun %integer->octets (n)
  "Non-negative integer -> minimal big-endian octet-vector (empty for 0)."
  (if (zerop n)
      (make-octet-vector 0)
      (let ((bytes '()))
        (loop while (plusp n)
              do (push (logand n #xff) bytes)
                 (setf n (ash n -8)))
        (coerce bytes 'octet-vector))))

(defun base58-encode (octets)
  "Encode an octet-vector to a Base58 string."
  (declare (type sequence octets))
  (let* ((octets (coerce octets 'octet-vector))
         (zeros (loop for b across octets while (zerop b) count t))
         (n (%octets->integer octets))
         (digits '()))
    (loop while (plusp n)
          do (multiple-value-bind (q r) (floor n 58)
               (push (char +base58-alphabet+ r) digits)
               (setf n q)))
    (concatenate 'string
                 (make-string zeros :initial-element #\1)
                 (coerce digits 'string))))

(defun %base58-index (ch)
  (or (position ch +base58-alphabet+)
      (error 'entity-core-error :detail (list :invalid-base58-char ch))))

(defun base58-decode (string)
  "Decode a Base58 STRING to an octet-vector (leading-zero preserving)."
  (declare (type string string))
  (let* ((ones (loop for ch across string while (char= ch #\1) count t))
         (n (loop with acc = 0
                  for ch across string
                  do (setf acc (+ (* acc 58) (%base58-index ch)))
                  finally (return acc)))
         (body (%integer->octets n)))
    (concatenate 'octet-vector
                 (make-array ones :element-type '(unsigned-byte 8) :initial-element 0)
                 body)))
