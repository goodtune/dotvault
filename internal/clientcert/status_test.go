package clientcert

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// reporterSource is a Source that also reports Last, recording any Current
// call so a test can prove StatusOf never signs.
type reporterSource struct {
	pair    *Pair
	err     error
	current int
}

func (r *reporterSource) Current(context.Context) (*Pair, error) { r.current++; return r.pair, r.err }
func (r *reporterSource) Last() (*Pair, error)                   { return r.pair, r.err }

func TestStatusOfNil(t *testing.T) {
	if got := StatusOf(nil); got != (Status{}) {
		t.Errorf("StatusOf(nil) = %+v, want zero", got)
	}
}

func TestStatusOfNotYetServedIsNotAnError(t *testing.T) {
	got := StatusOf(&reporterSource{})
	if got.State != StateIdle || got.LastError != "" {
		t.Errorf("StatusOf = %+v, want idle with no error", got)
	}
}

func TestStatusOfServing(t *testing.T) {
	na := time.Now().Add(time.Hour)
	src := &reporterSource{pair: &Pair{
		CertPEM: []byte("CERT"), KeyPEM: []byte("KEY"),
		Serial: "aa:bb", CommonName: "gary", NotAfter: na, Source: SourceEphemeral,
	}}
	got := StatusOf(src)
	if got.State != StateServing || got.Source != SourceEphemeral || got.CommonName != "gary" || got.Serial != "aa:bb" || !got.NotAfter.Equal(na) {
		t.Errorf("StatusOf = %+v", got)
	}
	if src.current != 0 {
		t.Error("StatusOf called Current")
	}
}

func TestStatusOfError(t *testing.T) {
	got := StatusOf(&reporterSource{err: errors.New("boom")})
	if got.State != StateError || !strings.Contains(got.LastError, "boom") {
		t.Errorf("StatusOf = %+v", got)
	}
}
