;;;; type-registry.lisp — the §9.5 type-registry byte-diff (peer-side dual of the
;;;; S2 codec corpus). Renders all 53 core types (§9.5) from the in-code model
;;;; (+core-type-models+) and diffs each content_hash against the canonical
;;;; type-registry-vectors-v1.diag (the cross-impl Go-rendered registry). Proves
;;;; render-from-model is byte-identical to the oracle's TypeDefinition entities.
;;;;
;;;; Each .diag line looks like:
;;;;   { "name": "X", "tree_path": "...", "content_hash": "ecf-sha256:<64hex>",
;;;;     "data": h'...' }
;;;; We extract name -> 64-hex digest and compare against our entity-hash digest.

(defpackage #:entity-core/type-registry
  (:use #:cl)
  (:export #:run-type-registry))

(in-package #:entity-core/type-registry)

(defun %field-after (line key)
  "Return the substring inside the double-quotes following \"KEY\": in LINE, or NIL."
  (let* ((needle (concatenate 'string "\"" key "\": \""))
         (start (search needle line)))
    (when start
      (let* ((vstart (+ start (length needle)))
             (vend (position #\" line :start vstart)))
        (when vend (subseq line vstart vend))))))

(defun parse-diag (path)
  "name -> 64-hex content_hash digest, from the .diag vectors."
  (let ((tbl (make-hash-table :test 'equal)))
    (with-open-file (in path :direction :input :external-format :utf-8)
      (loop for line = (read-line in nil :eof)
            until (eq line :eof)
            do (let ((name (%field-after line "name"))
                     (ch (%field-after line "content_hash")))
                 (when (and name ch)
                   ;; strip the "ecf-sha256:" prefix
                   (let ((colon (position #\: ch)))
                     (setf (gethash name tbl)
                           (if colon (subseq ch (1+ colon)) ch)))))))
    tbl))

(defun run-type-registry (diag-path)
  "Diff the 53 rendered core types against DIAG-PATH; returns T iff all match."
  (let ((expected (parse-diag diag-path))
        (pass 0) (fail 0))
    (dolist (pair (ecp:core-type-entities))
      (let* ((name (car pair))
             (e (cdr pair))
             ;; our hash is 33 bytes: format byte 0x00 ‖ 32-byte digest. Compare digest.
             (full (ecp:entity-hash e))
             (digest-hex (string-downcase (ecp:hex (subseq full 1))))
             (exp (gethash name expected)))
        (cond
          ((and exp (string= exp digest-hex)) (incf pass))
          (exp (incf fail)
               (format t "FAIL ~a~%  expected ~a~%  got      ~a~%" name exp digest-hex))
          (t (incf fail) (format t "FAIL ~a — not found in vectors~%" name)))))
    (format t "type-registry: ~d/~d byte-identical~%" pass (+ pass fail))
    (zerop fail)))
