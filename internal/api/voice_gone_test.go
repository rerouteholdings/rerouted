package api

import (
	"testing"

	"github.com/rerouteholdings/rerouted/internal/sfu"
)

// fakeVoice is an SFU whose rooms have whoever `in` says.
type fakeVoice struct{ in map[string]bool }

func (f fakeVoice) Room(string) sfu.VoiceRoom { return fakeRoom{f} }
func (f fakeVoice) Close() error              { return nil }

type fakeRoom struct{ f fakeVoice }

func (r fakeRoom) Join(sfu.Member, string, int, bool, sfu.Signal) (string, error) { return "", nil }
func (r fakeRoom) NewVisit(string, uint32) error                                  { return nil }
func (r fakeRoom) Leave(string) bool                                              { return false }
func (r fakeRoom) Remote(string, string) (string, error)                          { return "", nil }
func (r fakeRoom) ICE(string, string) error                                       { return nil }
func (r fakeRoom) SetVoice(string, bool)                                          {}
func (r fakeRoom) SetCast(string, []string, int) error                            { return nil }
func (r fakeRoom) State() []sfu.Participant                                       { return nil }
func (r fakeRoom) Has(key string) bool                                            { return r.f.in[key] }
func (r fakeRoom) Len() int                                                       { return len(r.f.in) }

// News that a device's connection ended, arriving after the device joined again, is of the
// old connection: the new visit stays.
func TestStaleGone(t *testing.T) {
	rec := &visitRec{id: "tr:x", channel: 1, visit: 2}
	v := &voiceRooms{c: &community{name: "c.test"}, sfu: fakeVoice{in: map[string]bool{"kat": true}}, at: map[string]*visitRec{"kat": rec}}
	v.gone("kat")
	if v.at["kat"] != rec {
		t.Fatal("a device that joined again was dropped with its old connection")
	}
	v.gone("nobody") // not in a channel: nothing to do
}
