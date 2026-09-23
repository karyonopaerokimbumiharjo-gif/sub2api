package service

// ForwardResponseWrittenError marks a complete error response written by the
// forwarding layer. The handler must still verify that bytes were written.
// A stream read error after a heartbeat must not use this marker.
type ForwardResponseWrittenError struct{ Err error }

func (e *ForwardResponseWrittenError) Error() string { return e.Err.Error() }
func (e *ForwardResponseWrittenError) Unwrap() error { return e.Err }
