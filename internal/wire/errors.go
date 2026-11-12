package wire

// Error is the error body every non-2xx response carries (SPEC §4.4).
type Error struct {
	Code  string  `json:"error"`
	Msg   string  `json:"msg,omitempty"`
	Retry uint64  `json:"retry,omitempty"`
	IDs   []Bytes `json:"ids,omitempty"` // the deliveries an error is about (SPEC §4.4)
	Now   int64   `json:"now,omitempty"` // with clock-skew: the server's clock (SPEC §8.4)
}

func (e *Error) Error() string {
	if e.Msg != "" {
		return e.Code + ": " + e.Msg
	}
	return e.Code
}

// Error codes from spec/api/conventions.md.
const (
	ErrCodeBadRequest         = "bad-request"
	ErrCodeUnknownKind        = "unknown-kind"
	ErrCodeBadContentType     = "bad-content-type"
	ErrCodeBadSignature       = "bad-signature"
	ErrCodeInvalidChain       = "invalid-chain"
	ErrCodeClockSkew          = "clock-skew"
	ErrCodeUnauthenticated    = "unauthenticated"
	ErrCodeNotAllowed         = "not-allowed"
	ErrCodeRegistrationClosed = "registration-closed"
	ErrCodeNotFound           = "not-found"
	ErrCodeHandleTaken        = "handle-taken"
	ErrCodeStaleHead          = "stale-head"
	ErrCodeStaleEpoch         = "stale-epoch"
	ErrCodeStaleVersion       = "stale-version"
	ErrCodeAlreadyExists      = "already-exists"
	ErrCodeExpired            = "expired"
	ErrCodeRemoved            = "removed"
	ErrCodeTooLarge           = "too-large"
	ErrCodeOverQuota          = "over-quota"
	ErrCodeRateLimited        = "rate-limited"
	ErrCodeUnavailable        = "unavailable"
	ErrCodeNotImplemented     = "not-implemented"
	ErrCodeBadInvite          = "bad-invite"
	ErrCodeAwaitingKey        = "awaiting-key"
	ErrCodeWrongHome          = "wrong-home"
)
