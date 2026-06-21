;;;; cbor.lisp — Entity Canonical Form (ECF) hand-rolled canonical CBOR codec.
;;;;
;;;; ENTITY-CBOR-ENCODING.md v1.5 (spec-data v7.72). No CL CBOR library gives ECF's
;;;; guarantees, so the canonical layer is owned here (profile [codec]):
;;;;   * minimal integer encoding (Rule 1) — native bignums, NO width special-casing
;;;;   * map keys sorted by ENCODED LENGTH then byte-lexicographic (Rule 2 / §3.5)
;;;;   * definite lengths only (Rule 3)
;;;;   * shortest float preserving value, incl. f16 (Rule 4) + Rule-4a special bytes
;;;;   * recursive major-type-6 (tag) rejection on decode (invariant N2; §6.3)
;;;;   * empty map = the single byte 0xA0 (invariant N3)
;;;;
;;;; Value representation (decoded form). External wire data is kept case-EXACT and
;;;; is never routed through CL symbols (the case-insensitive-reader footgun):
;;;;   CBOR unsigned/negative int  <-> CL integer (bignum)
;;;;   CBOR float (finite)         <-> CL double-float
;;;;   CBOR NaN/+Inf/-Inf/-0.0     <-> +nan+ / +inf+ / +neg-inf+ / +neg-zero+
;;;;   CBOR text string            <-> CL string
;;;;   CBOR byte string            <-> (bytes <octet-vector>)  struct wrapper
;;;;   CBOR array                  <-> CL list
;;;;   CBOR map                    <-> alist ((key . value) ...)  [order-preserving]
;;;;   CBOR true/false/null        <-> t / nil-is-false? NO: :false / :true / :null
;;;;
;;;; Booleans + null use keyword sentinels (:true :false :null) rather than CL t/nil
;;;; so an empty map (`()` alist) is never confused with null and a map value of
;;;; false is distinct from "absent" — ECF requires absent != null != zero/false.

(in-package #:entity-core)

(defconstant +max-depth+ 64 "ECF §10.2 nesting depth limit.")

;; ── float / boolean / null sentinels ────────────────────────────────────────
(defparameter +nan+      :nan)
(defparameter +inf+      :inf)
(defparameter +neg-inf+  :neg-inf)
(defparameter +neg-zero+ :neg-zero)

;; ── byte-string wrapper (distinguishes major type 2 from major type 3) ───────
(defstruct (bytes (:constructor make-bytes (octets)))
  (octets (make-octet-vector 0) :type octet-vector :read-only t))

(defun bytes (octets)
  "Wrap OCTETS (a sequence of (unsigned-byte 8)) as a CBOR byte string value."
  (make-bytes (coerce octets 'octet-vector)))

;; ── map representation ───────────────────────────────────────────────────────
;; A map is an explicit object carrying an alist of (key . value) pairs, so it is
;; never confused with an array (a list) or null. Keys are strings or `bytes`.
;; (Defined before the encoder so cbor-map-p is in scope without a forward ref.)
(defstruct (cbor-map (:constructor make-cbor-map (pairs)))
  (pairs nil :type list :read-only t))

(defun map-of (&rest kvs)
  "Build a cbor-map from alternating key value ... arguments (convenience)."
  (let ((pairs '()))
    (loop for (k v) on kvs by #'cddr do (push (cons k v) pairs))
    (make-cbor-map (nreverse pairs))))

(defun alist->map (alist) (make-cbor-map (copy-alist alist)))

;; ═════════════════════════════════════════════════════════════════════════════
;; Encode
;; ═════════════════════════════════════════════════════════════════════════════

(defun cbor-encode (value)
  "Encode VALUE to canonical ECF bytes (an octet-vector)."
  (let ((out (make-array 64 :element-type '(unsigned-byte 8)
                            :adjustable t :fill-pointer 0)))
    (%enc value out)
    (coerce out 'octet-vector)))

(declaim (inline %push-octet %push-octets))
(defun %push-octet (b out) (vector-push-extend b out))
(defun %push-octets (seq out)
  (etypecase seq
    (vector (loop for b across seq do (vector-push-extend b out)))
    (list (loop for b in seq do (vector-push-extend b out)))))

(defun %enc-head (major arg out)
  "Emit a CBOR initial byte for MAJOR (0-7) with the shortest argument for ARG."
  (let ((m (ash major 5)))
    (cond
      ((< arg 24)        (%push-octet (logior m arg) out))
      ((< arg #x100)     (%push-octet (logior m 24) out)
                         (%push-octet arg out))
      ((< arg #x10000)   (%push-octet (logior m 25) out)
                         (%push-octet (ldb (byte 8 8) arg) out)
                         (%push-octet (ldb (byte 8 0) arg) out))
      ((< arg #x100000000)
       (%push-octet (logior m 26) out)
       (dotimes (i 4) (%push-octet (ldb (byte 8 (* 8 (- 3 i))) arg) out)))
      ((< arg #x10000000000000000)
       (%push-octet (logior m 27) out)
       (dotimes (i 8) (%push-octet (ldb (byte 8 (* 8 (- 7 i))) arg) out)))
      (t (error 'entity-core-error :detail (list :uint-too-large arg))))))

(defun %enc (value out)
  (cond
    ;; Float / boolean / null sentinels (keywords) — match before generic atoms.
    ((eq value +nan+)      (%push-octets #(#xf9 #x7e #x00) out))
    ((eq value +inf+)      (%push-octets #(#xf9 #x7c #x00) out))
    ((eq value +neg-inf+)  (%push-octets #(#xf9 #xfc #x00) out))
    ((eq value +neg-zero+) (%push-octets #(#xf9 #x80 #x00) out))
    ((eq value :true)      (%push-octet #xf5 out))
    ((eq value :false)     (%push-octet #xf4 out))
    ((eq value :null)      (%push-octet #xf6 out))
    ;; Integers (major 0 / 1), minimal encoding. Native bignums, no width trap.
    ((integerp value)
     (if (>= value 0)
         (%enc-head 0 value out)
         (%enc-head 1 (- (- value) 1) out)))
    ;; Finite floats — shortest encoding preserving value.
    ((floatp value) (%enc-float (coerce value 'double-float) out))
    ;; Byte string (major 2).
    ((bytes-p value)
     (let ((o (bytes-octets value)))
       (%enc-head 2 (length o) out)
       (%push-octets o out)))
    ;; Text string (major 3) — UTF-8 octets.
    ((stringp value)
     (let ((o (string-to-utf8 value)))
       (%enc-head 3 (length o) out)
       (%push-octets o out)))
    ;; Array (major 4).
    ((listp value)
     ;; () = empty array; non-empty proper list of items.
     (%enc-head 4 (length value) out)
     (dolist (item value) (%enc item out)))
    ;; Map (major 5) — represented as an entity-core map object.
    ((cbor-map-p value)
     (%enc-map (cbor-map-pairs value) out))
    (t (error 'entity-core-error :detail (list :cannot-encode value)))))

(defun %enc-map (pairs out)
  "Encode PAIRS (alist) as a canonical CBOR map: sort by encoded-key length then
byte-lexicographic (ECF Rule 2 / §3.5)."
  (let ((encoded (mapcar (lambda (p)
                           (cons (cbor-encode (car p)) (cbor-encode (cdr p))))
                         pairs)))
    (setf encoded (stable-sort encoded #'%key<
                               :key #'car))
    (%enc-head 5 (length encoded) out)
    (dolist (e encoded)
      (%push-octets (car e) out)
      (%push-octets (cdr e) out))))

(defun %key< (a b)
  "Length-then-lexicographic order on two encoded-key octet-vectors (ECF Rule 2)."
  (let ((la (length a)) (lb (length b)))
    (cond ((< la lb) t)
          ((> la lb) nil)
          (t (loop for x across a for y across b
                   do (cond ((< x y) (return t))
                            ((> x y) (return nil)))
                   finally (return nil))))))

;; ── float ladder: f16 ⊂ f32 ⊂ f64, shortest that round-trips exactly ────────
(defun %enc-float (f out)
  "Encode a finite double-float F to the shortest IEEE form preserving value."
  (cond
    ;; -0.0 is canonical f16 (Rule 4a). (+0.0 falls through to the f16 path -> f90000.)
    ((and (zerop f) (minusp (float-sign f)))
     (%push-octets #(#xf9 #x80 #x00) out))
    (t
     (let ((h (float->f16 f)))
       (if (and h (= (f16->double h) f))
           (progn (%push-octet #xf9 out)
                  (%push-octet (ldb (byte 8 8) h) out)
                  (%push-octet (ldb (byte 8 0) h) out))
           (let ((s (float->f32-bits f)))
             (if (and s (= (f32-bits->double s) f))
                 (progn (%push-octet #xfa out)
                        (dotimes (i 4) (%push-octet (ldb (byte 8 (* 8 (- 3 i))) s) out)))
                 (let ((d (double->f64-bits f)))
                   (%push-octet #xfb out)
                   (dotimes (i 8) (%push-octet (ldb (byte 8 (* 8 (- 7 i))) d) out))))))))))

;; ═════════════════════════════════════════════════════════════════════════════
;; IEEE 754 conversions (bit-exact, no FFI)
;; ═════════════════════════════════════════════════════════════════════════════

(defun double->f64-bits (f)
  "Finite double-float -> its 64-bit IEEE bit pattern (integer)."
  (multiple-value-bind (hi lo) (sb-kernel:double-float-bits f)
    ;; SBCL: double-float-bits returns the full 64-bit pattern on 64-bit builds.
    (declare (ignore lo))
    (logand hi #xffffffffffffffff)))

;; Portable bit extraction via integer-decode-float (works on any conforming CL).
(defun %double-fields (f)
  "Return (values sign biased-exp 52-bit-mantissa) for a finite double F."
  (if (zerop f)
      (values (if (minusp (float-sign f)) 1 0) 0 0)
      (multiple-value-bind (mant expo sign) (integer-decode-float f)
        ;; mant is 53-bit (with implicit leading 1); expo is the 2-exponent of mant.
        ;; Normalize to IEEE: value = mant * 2^expo, mant in [2^52, 2^53).
        (let* ((s (if (minusp sign) 1 0))
               (e (+ expo 52 1023)))  ; biased exponent for normalized doubles
          (cond
            ((>= e 2047) (values s 2047 0)) ; overflow -> inf (shouldn't hit finite)
            ((<= e 0)
             ;; subnormal double: shift mantissa right
             (let ((shift (- 1 e)))
               (values s 0 (ash mant (- shift)))))
            (t (values s e (logand mant #xfffffffffffff))))))))

(defun f64-bits->double (bits)
  (sb-kernel:make-double-float
   (ash (logand bits #xffffffff00000000) -32)        ; high word (signed-ish ok)
   (logand bits #xffffffff)))

;; --- f32 ---
(defun float->f32-bits (f)
  "Convert finite double F to 32-bit IEEE bits if it round-trips exactly, else NIL."
  (let* ((sf (ignore-errors (coerce f 'single-float))))
    (when sf
      (let ((bits (sb-kernel:single-float-bits sf)))
        (let ((u (logand bits #xffffffff)))
          ;; reject if exponent all-ones (would be inf/nan via overflow)
          (if (= (ldb (byte 8 23) u) #xff)
              nil
              u))))))

(defun f32-bits->double (u)
  (coerce (sb-kernel:make-single-float
           (if (>= u #x80000000) (- u #x100000000) u))
          'double-float))

;; --- f16 (half) --- pure-integer, exact ---
(defun float->f16 (f)
  "Convert finite double F to a 16-bit IEEE half bit pattern, or NIL if the value
is not exactly representable as a finite f16 (so the caller falls back to f32/f64)."
  (multiple-value-bind (s e m) (%double-fields f)
    (if (zerop f)
        (if (= s 1) #x8000 #x0000)
        (let* ((unbiased (- e 1023))          ; true exponent
               (he (+ unbiased 15)))          ; half biased exponent
          (cond
            ;; too large for finite f16 (max normal exp = 30)
            ((> he 30) nil)
            ;; normalized f16
            ((>= he 1)
             ;; mantissa: double has 52 bits; half has 10. Need exact fit.
             (if (zerop (logand m #x3ffffffffff)) ; low 42 bits must be 0
                 (logior (ash s 15) (ash he 10) (ash m -42))
                 nil))
            ;; subnormal f16 (he <= 0): value = (1.m) * 2^unbiased, exactly
            ;; representable iff value * 2^24 is an integer in [1,1023].
            (t
             (let* ((full (logior #x10000000000000 m))   ; implicit leading 1 (53-bit)
                    (scaled (* full (expt 2 (+ (- unbiased 52) 24)))))
               (if (and (integerp scaled) (<= 1 scaled 1023))
                   (logior (ash s 15) scaled)
                   nil))))))))

(defun f16->double (h)
  "Convert a 16-bit IEEE half bit pattern H to a double-float (finite values only)."
  (let* ((s (ldb (byte 1 15) h))
         (e (ldb (byte 5 10) h))
         (m (ldb (byte 10 0) h))
         (sign (if (= s 1) -1d0 1d0)))
    (cond
      ((= e 0)
       (if (zerop m)
           (* sign 0d0)
           (* sign (* m (expt 2d0 -24)))))            ; subnormal
      ((= e #x1f)
       ;; inf/nan — not produced on the round-trip-exact path; return inf marker
       (if (zerop m) (* sign sb-ext:double-float-positive-infinity) :nan))
      (t (* sign (* (+ 1024 m) (expt 2d0 (- e 25))))))))  ; (1.m)*2^(e-15), m/1024

;; ═════════════════════════════════════════════════════════════════════════════
;; UTF-8 (text strings)
;; ═════════════════════════════════════════════════════════════════════════════

(defun string-to-utf8 (s)
  (sb-ext:string-to-octets s :external-format :utf-8))

(defun utf8-to-string (octets)
  (sb-ext:octets-to-string octets :external-format :utf-8))

;; ═════════════════════════════════════════════════════════════════════════════
;; Decode
;; ═════════════════════════════════════════════════════════════════════════════

(defun cbor-decode (octets &key (start 0) (require-end t))
  "Decode canonical ECF OCTETS to a value. Signals on tags (N2), truncation,
indefinite lengths, and (when REQUIRE-END) trailing bytes."
  (let ((o (coerce octets 'octet-vector)))
    (multiple-value-bind (value next) (%dec o start 0)
      (when (and require-end (< next (length o)))
        (error 'non-canonical-ecf :detail (list :trailing-bytes (- (length o) next))))
      (values value next))))

(defun cbor-decode-safe (octets &rest args)
  "Value-return wrapper: returns (values value nil) or (values nil condition)."
  (handler-case (values (apply #'cbor-decode octets args) nil)
    (entity-core-error (c) (values nil c))))

(defun %dec (o i depth)
  (when (> depth +max-depth+)
    (error 'non-canonical-ecf :detail :max-depth))
  (when (>= i (length o))
    (error 'truncated-input :detail :item))
  (let* ((ib (aref o i))
         (major (ash ib -5))
         (info (logand ib #x1f)))
    (incf i)
    (ecase major
      (0 (multiple-value-bind (arg ni) (%dec-arg o i info) (values arg ni)))
      (1 (multiple-value-bind (arg ni) (%dec-arg o i info) (values (- (- arg) 1) ni)))
      (2 (multiple-value-bind (len ni) (%dec-arg o i info)
           (%need o ni len)
           (values (make-bytes (subseq o ni (+ ni len))) (+ ni len))))
      (3 (multiple-value-bind (len ni) (%dec-arg o i info)
           (%need o ni len)
           (values (utf8-to-string (subseq o ni (+ ni len))) (+ ni len))))
      (4 (multiple-value-bind (len ni) (%dec-arg o i info)
           (%dec-array o ni len depth)))
      (5 (multiple-value-bind (len ni) (%dec-arg o i info)
           (%dec-map o ni len depth)))
      (6 (error 'tag-rejected :detail (list :major-6 :at i))) ; N2 — hard reject
      (7 (%dec-simple o i info)))))

(defun %need (o i len)
  (when (> (+ i len) (length o))
    (error 'truncated-input :detail (list :need len :at i))))

(defun %dec-arg (o i info)
  "Decode the argument for majors 0-5 from INFO + following bytes.
Rejects reserved (28-30) and indefinite (31) — ECF is definite-length only."
  (cond
    ((< info 24) (values info i))
    ((= info 24) (%need o i 1) (values (aref o i) (+ i 1)))
    ((= info 25) (%need o i 2)
                 (values (logior (ash (aref o i) 8) (aref o (+ i 1))) (+ i 2)))
    ((= info 26) (%need o i 4)
                 (values (loop with v = 0 for k below 4
                               do (setf v (logior (ash v 8) (aref o (+ i k))))
                               finally (return v))
                         (+ i 4)))
    ((= info 27) (%need o i 8)
                 (values (loop with v = 0 for k below 8
                               do (setf v (logior (ash v 8) (aref o (+ i k))))
                               finally (return v))
                         (+ i 8)))
    (t (error 'non-canonical-ecf :detail (list :bad-argument info)))))

(defun %dec-array (o i len depth)
  (let ((items '()))
    (dotimes (k len)
      (multiple-value-bind (v ni) (%dec o i (1+ depth))
        (push v items)
        (setf i ni)))
    (values (nreverse items) i)))

(defun %dec-map (o i len depth)
  (let ((pairs '()) (seen (make-hash-table :test 'equal)))
    (dotimes (k len)
      (multiple-value-bind (key ni) (%dec o i (1+ depth))
        (setf i ni)
        (multiple-value-bind (val nj) (%dec o i (1+ depth))
          (setf i nj)
          (let ((hk (%key-hash key)))
            (when (gethash hk seen)
              (error 'duplicate-map-key :detail key))
            (setf (gethash hk seen) t))
          (push (cons key val) pairs))))
    (values (make-cbor-map (nreverse pairs)) i)))

(defun %key-hash (key)
  "A hashable surrogate for a map key (string or bytes)."
  (etypecase key
    (string (cons :s key))
    (bytes (cons :b (coerce (bytes-octets key) 'list)))
    (integer (cons :i key))))

(defun %dec-simple (o i info)
  (cond
    ((= info 20) (values :false i))
    ((= info 21) (values :true i))
    ((= info 22) (values :null i))
    ((= info 25) (%need o i 2)
                 (values (decode-f16 (aref o i) (aref o (+ i 1))) (+ i 2)))
    ((= info 26) (%need o i 4)
                 (values (decode-f32 (subseq o i (+ i 4))) (+ i 4)))
    ((= info 27) (%need o i 8)
                 (values (decode-f64 (subseq o i (+ i 8))) (+ i 8)))
    (t (error 'non-canonical-ecf :detail (list :bad-simple info)))))

(defun decode-f16 (b0 b1)
  (let* ((h (logior (ash b0 8) b1))
         (s (ldb (byte 1 15) h)) (e (ldb (byte 5 10) h)) (m (ldb (byte 10 0) h)))
    (cond
      ((= e #x1f) (if (zerop m) (if (= s 1) +neg-inf+ +inf+) +nan+))
      ((and (= e 0) (= m 0)) (if (= s 1) +neg-zero+ 0d0))
      (t (f16->double h)))))

(defun decode-f32 (b)
  (let* ((u (loop with v = 0 for x across b do (setf v (logior (ash v 8) x))
                  finally (return v)))
         (s (ldb (byte 1 31) u)) (e (ldb (byte 8 23) u)) (m (ldb (byte 23 0) u)))
    (cond
      ((= e #xff) (if (zerop m) (if (= s 1) +neg-inf+ +inf+) +nan+))
      ((and (= e 0) (= m 0)) (if (= s 1) +neg-zero+ 0d0))
      (t (f32-bits->double u)))))

(defun decode-f64 (b)
  (let* ((u (loop with v = 0 for x across b do (setf v (logior (ash v 8) x))
                  finally (return v)))
         (s (ldb (byte 1 63) u)) (e (ldb (byte 11 52) u)) (m (ldb (byte 52 0) u)))
    (cond
      ((= e #x7ff) (if (zerop m) (if (= s 1) +neg-inf+ +inf+) +nan+))
      ((and (= e 0) (= m 0)) (if (= s 1) +neg-zero+ 0d0))
      (t (f64-bits->double u)))))
