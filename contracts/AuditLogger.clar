(define-constant ERR_NOT_AUTHORIZED u100)
(define-constant ERR_INVALID_SESSION_ID u101)
(define-constant ERR_INVALID_EVENT_TYPE u102)
(define-constant ERR_INVALID_TIMESTAMP u103)
(define-constant ERR_EVENT_NOT_FOUND u104)
(define-constant ERR_ACCESS_DENIED u105)
(define-constant ERR_INVALID_ROLE u106)
(define-constant ERR_INVALID_LOG_LIMIT u107)
(define-constant ERR_INVALID_AUTHORITY u108)
(define-constant ERR_MAX_EVENTS_EXCEEDED u109)

(define-data-var event-counter uint u0)
(define-data-var max-events uint u1000000)
(define-data-var authority-contract (optional principal) none)
(define-data-var allowed-roles (list 10 (string-ascii 20)) (list "patient" "doctor" "auditor"))

(define-map events
  uint
  {
    session-id: (string-ascii 64),
    event-type: (string-ascii 32),
    user: principal,
    timestamp: uint,
    role: (string-ascii 20),
    metadata-hash: (buff 32)
  }
)

(define-map session-logs
  (string-ascii 64)
  (list 1000 uint)
)

(define-read-only (get-event (event-id uint))
  (map-get? events event-id)
)

(define-read-only (get-session-logs (session-id (string-ascii 64)))
  (default-to (list) (map-get? session-logs session-id))
)

(define-read-only (get-event-count)
  (var-get event-counter)
)

(define-read-only (is-role-allowed (role (string-ascii 20)))
  (is-some (index-of (var-get allowed-roles) role))
)

(define-private (validate-session-id (session-id (string-ascii 64)))
  (if (and (> (len session-id) u0) (<= (len session-id) u64))
    (ok true)
    (err ERR_INVALID_SESSION_ID))
)

(define-private (validate-event-type (event-type (string-ascii 32)))
  (if (or
        (is-eq event-type "session-start")
        (is-eq event-type "session-end")
        (is-eq event-type "consent-granted")
        (is-eq event-type "consent-revoked")
        (is-eq event-type "data-access"))
    (ok true)
    (err ERR_INVALID_EVENT_TYPE))
)

(define-private (validate-timestamp (ts uint))
  (if (>= ts block-height)
    (ok true)
    (err ERR_INVALID_TIMESTAMP))
)

(define-private (validate-role (role (string-ascii 20)))
  (if (is-role-allowed role)
    (ok true)
    (err ERR_INVALID_ROLE))
)

(define-private (validate-metadata-hash (hash (buff 32)))
  (if (is-eq (len hash) u32)
    (ok true)
    (err ERR_INVALID_UPDATE_PARAM))
)

(define-private (validate-authority (user principal))
  (if (is-some (var-get authority-contract))
    (ok true)
    (err ERR_INVALID_AUTHORITY))
)

(define-public (set-authority-contract (contract-principal principal))
  (begin
    (asserts! (not (is-eq contract-principal 'SP000000000000000000002Q6VF78)) (err ERR_NOT_AUTHORIZED))
    (asserts! (is-none (var-get authority-contract)) (err ERR_INVALID_AUTHORITY))
    (var-set authority-contract (some contract-principal))
    (ok true)
  )
)

(define-public (log-event
  (session-id (string-ascii 64))
  (event-type (string-ascii 32))
  (role (string-ascii 20))
  (metadata-hash (buff 32))
)
  (let ((event-id (var-get event-counter))
        (current-max (var-get max-events)))
    (try! (validate-authority tx-sender))
    (try! (validate-session-id session-id))
    (try! (validate-event-type event-type))
    (try! (validate-timestamp block-height))
    (try! (validate-role role))
    (try! (validate-metadata-hash metadata-hash))
    (asserts! (< event-id current-max) (err ERR_MAX_EVENTS_EXCEEDED))
    (map-set events event-id
      {
        session-id: session-id,
        event-type: event-type,
        user: tx-sender,
        timestamp: block-height,
        role: role,
        metadata-hash: metadata-hash
      }
    )
    (map-set session-logs session-id
      (cons event-id (default-to (list) (map-get? session-logs session-id)))
    )
    (var-set event-counter (+ event-id u1))
    (print { event: "log-created", id: event-id, session: session-id })
    (ok event-id)
  )
)

(define-public (restrict-access
  (event-id uint)
  (role (string-ascii 20))
)
  (let ((event (map-get? events event-id)))
    (asserts! (is-some event) (err ERR_EVENT_NOT_FOUND))
    (asserts! (is-role-allowed role) (err ERR_INVALID_ROLE))
    (asserts! (is-eq (get role (unwrap! event (err ERR_EVENT_NOT_FOUND))) role) (err ERR_ACCESS_DENIED))
    (ok true)
  )
)