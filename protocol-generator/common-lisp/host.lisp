;;;; host.lisp — the standalone S4 conformance host.
;;;;
;;;; Boots a single Common Lisp peer listening on 127.0.0.1:PORT and prints a
;;;; `LISTENING 127.0.0.1:PORT` readiness line on stdout (the line run-s4.sh greps
;;;; for before pointing the Go `validate-peer` oracle at it). Then blocks the main
;;;; thread forever — the accept loop + per-connection serve threads do the work.
;;;;
;;;; Flags (cohort-consistent with the OCaml/TS/C# hosts):
;;;;   --port N            listen port (default 7777; 0 = auto)
;;;;   --debug-open-grants degenerate [default -> *] seed; grant-gated categories
;;;;                       need it (the cohort's explicitly non-conformant debug seed)
;;;;   --validate          bootstrap the §7a system/validate/* conformance handlers
;;;;                       (off by default; dispatch-outbound is a standing dialer)
;;;;   --seed B            fixed seed byte (default #x11) for a deterministic peer_id
;;;;   --name NAME         load a persistent Ed25519 identity from the standard on-disk
;;;;                       location ~/.entity/peers/NAME/keypair (the entity-core PEM
;;;;                       keypair: base64 of a 32-byte seed between BEGIN/END ENTITY
;;;;                       PRIVATE KEY lines — the same convention the Go entity-peer
;;;;                       --name and peer-manager use). Overrides --seed/default; the
;;;;                       validator's multisig accept-path probe co-signs AS the peer,
;;;;                       so it needs the keypair on disk (crypto.LookupKeypairByPeerID).

(defpackage #:entity-core/host
  (:use #:cl)
  (:export #:main))

(in-package #:entity-core/host)

(defun arg-value (args flag &optional default)
  (let ((tail (member flag args :test #'string=)))
    (if (and tail (cdr tail)) (second tail) default)))

(defun arg-flag (args flag)
  (and (member flag args :test #'string=) t))

(defun fixed-seed (byte)
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element byte))

;; Decode standard-alphabet base64 (ignores whitespace + padding) → octet vector.
;; Hand-rolled to keep the peer's zero-dependency posture (cf. OCaml's b64_decode).
(defun b64-decode (string)
  (flet ((val (c)
           (cond ((char<= #\A c #\Z) (- (char-code c) 65))
                 ((char<= #\a c #\z) (- (char-code c) 71))
                 ((char<= #\0 c #\9) (+ (char-code c) 4))
                 ((char= c #\+) 62)
                 ((char= c #\/) 63)
                 (t -1))))
    (let ((out (make-array 0 :element-type '(unsigned-byte 8)
                             :adjustable t :fill-pointer 0))
          (acc 0) (bits 0))
      (loop for c across string
            for v = (val c)
            when (>= v 0) do
              (setf acc (logior (ash acc 6) v))
              (incf bits 6)
              (when (>= bits 8)
                (decf bits 8)
                (vector-push-extend (logand (ash acc (- bits)) #xff) out)))
      out)))

;; Load the 32-byte Ed25519 seed from the standard on-disk keypair (Go entity-peer
;; --name / peer-manager): ~/.entity/peers/NAME/keypair, a PEM whose body is
;; base64(seed) between BEGIN/END ENTITY PRIVATE KEY lines. Missing/malformed → quit 2.
(defun load-seed-from-name (name)
  (let* ((home (or (uiop:getenv "HOME") (namestring (user-homedir-pathname))))
         (path (merge-pathnames
                (make-pathname :directory (list :relative ".entity" "peers" name)
                               :name "keypair")
                (uiop:ensure-directory-pathname home))))
    (handler-case
        (let* ((lines (uiop:read-file-lines path))
               (body (with-output-to-string (s)
                       (dolist (l lines)
                         (unless (and (> (length l) 0) (char= (char l 0) #\-))
                           (write-string (string-trim '(#\Space #\Tab #\Return) l) s)))))
               (seed (b64-decode body)))
          (unless (= (length seed) 32)
            (format *error-output*
                    "error: --name ~a: expected a 32-byte seed, got ~d bytes~%"
                    name (length seed))
            (uiop:quit 2))
          (make-array 32 :element-type '(unsigned-byte 8) :initial-contents seed))
      (error (e)
        (format *error-output* "error: --name ~a: ~a~%" name e)
        (uiop:quit 2)))))

(defun main ()
  (let* ((args (cdr sb-ext:*posix-argv*))
         (port (parse-integer (arg-value args "--port" "7777")))
         (open-grants (arg-flag args "--debug-open-grants"))
         (validate (arg-flag args "--validate"))
         (name (arg-value args "--name"))
         (seed-byte (parse-integer (arg-value args "--seed" "17")))
         (seed (if name (load-seed-from-name name) (fixed-seed seed-byte)))
         (peer (ecp:make-peer :seed seed
                              :open-grants open-grants
                              :conformance validate)))
    (multiple-value-bind (sock bound thread) (ecp:start-listener peer port)
      (declare (ignore sock))
      ;; readiness line — run-s4.sh greps `^LISTENING`.
      (format t "LISTENING 127.0.0.1:~a peer=~a open-grants=~a validate=~a~%"
              bound (ecp:peer-local-peer peer) open-grants validate)
      (finish-output)
      ;; block forever on the accept thread.
      (sb-thread:join-thread thread))))
