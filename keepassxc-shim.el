;;; keepassxc-shim.el --- Shim between KeePassXC and secrets.el -*- lexical-binding: t; -*-

;; Author: Case Duckworth <acdw@acdw.net>
;; Version: 0.1.0
;; License: ISC
;; URL: https://github.com/duckwork/keypassxc-shim.el
;; Package-Requires: ((emacs "25.1"))
;; Keywords: comm password passphrase convenience

;;; Commentary:

;; Emacs interfaces with Freedesktop's [[https://specifications.freedesktop.org/secret-service//latest/][Secret-Service]], and so does [[https://keepassxc.org/][KeePassXC]].
;; However, to get these two to work together, a little bit more glue is
;; necessary.

;; KeePassXC stores keys like `:UserName' and `:URL', whereas the `auth-source'
;; library, while technically backend-agnostic, advises and tends to expect keys
;; like `:user' and `:host'.

;; This shim makes working with KeePassXC-backed secret stores just a little
;; easier to work with, especially when also using other auth-sources like
;; ~/.authinfo, etc.  Maybe this isn't the best idea; in fact, maybe it's simply
;; terrible.  Whatever, says I.

;;; Code:

(require 'auth-source)
(require 'cl-lib)
(require 'secrets)

(defgroup keepassxc-shim nil
  "Customizations for the KeePassXC shim."
  :group 'applications
  :group 'auth-source
  :prefix "keepassxc-shim-")

(defcustom keepassxc-shim-how 'fallback
  "How to access KeePassXC secrets.
This option determines how KeePassXC-style secrets will be
searched in addition to authinfo-style secrets.  It can be one of
the following:

- `fallback': Authinfo-style keys will be searched first, then
  KeePassXC-style as a fallback.

- `priority': KeePassXC-style keys will be searched first, then
  authinfo-style.

- `replace': Only KeePassXC-style keys will be searched.

- `remove': Disable the shim altogether."
  :type '(choice (const :tag "KeePassXC-style as a fallback" fallback)
                 (const :tag "Authinfo-style as a fallback" priority)
                 (const :tag "Only search KeePassXC-style" replace)
                 (const :tag "Disable" remove)))

(defcustom keepassxc-shim-keys-transform '((:host . :URL)
                                           (:user . :UserName))
  "Alist of transformations on keys.
The car of a key is its auth-source style, and the cdr is its
KeePassXC style."
  :type '(alist :key-type symbol
                :value-type symbol))

(defun keepassxc-shim--filter-args (args)
  "Convert the ARGS to `auth-source-search' between styles.
This converts them rom auth-source style to KeePassXC style."
  (cl-loop for arg in plist
           collect (or (alist-get arg keepassxc-shim-keys-transform)
                       arg)))

(cl-defun keepassxc-shim--auth-source-search (&rest spec
                                                    &key max require _create _delete
                                                    &allow-other-keys)
  "`Keepassxc-shim' copy of `auth-source-search'.
This is a simplified copy of `auth-source-search'.  I have to use
this on the fallback or else it will endlessly loop.

SPEC, MAX, and REQUIRE are as in `auth-source-search'.  CREATE
and DELETE are ignored.

This is just as cursed as it seems."
  (let* ((backends (mapcar #'auth-source-backend-parse auth-sources))
         (max (or max 1))
         (ignored-keys '(:require :create :delete :max))
         (keys (cl-loop for i below (length spec) by 2
                        unless (memq (nth i spec) ignored-keys)
                        collect (nth i spec)))
         (filtered-backends (copy-sequence backends)))
    (dolist (backend backends)
      (cl-dolist (key keys)
        (condition-case nil
            (unless (auth-source-search-collection
                     (plist-get spec key)
                     (slot-value backend key))
              (setq filtered-backends (delq backend filtered-backends))
              (cl-return))
          (invalid-slot-name nil))))
    (auth-source-search-backends filtered-backends spec max nil nil require)))

(defun keepassxc-shim--fallback (&rest plist)
  "Fallback funtion to search for KeePassXC-style arguments.
PLIST is filtered then searched for in `auth-sources'."
  (apply #'keepassxc-shim--auth-source-search (keepassxc-shim--filter-args plist)))

;;;###autoload
(defun keepassxc-shim-activate (&optional how)
  "Activate the KeePassXC shim.
This advises `auth-source-search' in a way befitting HOW, which
can be any of the options in `keepassxc-shim-how'.  In fact, HOW
defaults to the value of `keepassxc-shim-how'."
  (cl-case (or how keepassxc-shim-how)
    (fallback (advice-add 'auth-source-search :after-until #'keepassxc-shim--fallback))
    (priority (advice-add 'auth-source-search :before-until #'keepassxc-shim--fallback))
    (replace (advice-add 'auth-source-search :filter-args #'keepassxc-shim--filter-args))
    (remove (advice-remove 'auth-source-search #'keepassxc-shim--fallback)
            (advice-remove 'auth-source-search #'keepassxc-shim--filter-args))))

;;;###autoload
(defun keepassxc-shim-deactivate ()
  "Deactivate the KeePassXC shim."
  (keepassxc-shim-activate 'remove))

;;; Import ~/.authinfo into KeePassXC
;; This isn't perfect or guaranteed to work, and honestly you probably won't use
;; it often, but it's a nice bit of kit that I whipped up that would be a shame
;; to waste.

;;;###autoload
(defun keepassxc-shim-import (&optional type)
  "Import a database of TYPE into `secret-store'.
The keys are specific to KeePassXC."
  (dolist (source (auth-source-search :type (or type 'netrc) :max 100))
    (let ((host (plist-get source :host))
          (user (plist-get source :user))
          (pass (if (functionp (plist-get source :secret))
                    (funcall (plist-get source :secret))
                  (plist-get source :secret)))
          (port (plist-get source :port))
          (attrs (cl-loop for (key val) on source by #'cddr
                          unless (member key '(:host :user :secret))
                          append (list key val) into ret
                          finally return ret)))
      (secrets-create-item "default" (concat user "@" host)
                           :UserName user
                           :URL host
                           :source "authinfo"))))

(provide 'keepassxc-shim)
;;; keepassxc-shim.el ends here
