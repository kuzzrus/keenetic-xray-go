package classifier

import (
	"testing"
	"time"
)

func TestTTLSet_AddHasRemove(t *testing.T) {
	now := time.Now()
	s := ttlSet{}
	if s.has("1.2.3.4", now) {
		t.Fatal("empty set should not have anything")
	}
	s.add("1.2.3.4", now, 10*time.Second)
	if !s.has("1.2.3.4", now) {
		t.Fatal("expected 1.2.3.4 to be present")
	}
	if !s.has("1.2.3.4", now.Add(9*time.Second)) {
		t.Fatal("expected 1.2.3.4 to still be present just before its TTL")
	}
	if s.has("1.2.3.4", now.Add(11*time.Second)) {
		t.Fatal("expected 1.2.3.4 to be gone past its TTL")
	}
	s.remove("1.2.3.4")
	if s.has("1.2.3.4", now) {
		t.Fatal("expected 1.2.3.4 to be gone after remove")
	}
}

func TestTTLSet_ZeroTTLNeverExpires(t *testing.T) {
	now := time.Now()
	s := ttlSet{}
	s.add("1.2.3.4", now, 0)
	if !s.has("1.2.3.4", now.Add(100*365*24*time.Hour)) {
		t.Error("ttl<=0 should mean it never expires")
	}
}

func TestTTLSet_AddOverwritesExpiry(t *testing.T) {
	now := time.Now()
	s := ttlSet{}
	s.add("1.2.3.4", now, 5*time.Second)
	s.add("1.2.3.4", now, 50*time.Second) // re-add -- must reset the TTL, not stack
	if !s.has("1.2.3.4", now.Add(10*time.Second)) {
		t.Error("re-adding should reset the TTL to the new value")
	}
}

func TestTTLSet_At(t *testing.T) {
	now := time.Now()
	s := ttlSet{}
	if !s.at("1.2.3.4", now).IsZero() {
		t.Error("at() on an absent entry should be the zero Time")
	}
	s.add("1.2.3.4", now, 10*time.Second)
	if got := s.at("1.2.3.4", now); got.IsZero() {
		t.Error("at() on a live entry should not be zero")
	}
	if !s.at("1.2.3.4", now.Add(11*time.Second)).IsZero() {
		t.Error("at() on an expired entry should be the zero Time")
	}
}

func TestTTLSet_Expire(t *testing.T) {
	now := time.Now()
	s := ttlSet{}
	s.add("live", now, time.Hour)
	s.add("dead", now, time.Second)
	s.expire(now.Add(2 * time.Second))
	if _, ok := s["dead"]; ok {
		t.Error("expire should have dropped the dead entry")
	}
	if _, ok := s["live"]; !ok {
		t.Error("expire should not touch a still-live entry")
	}
}

func TestState_ExpireAcrossAllSets(t *testing.T) {
	now := time.Now()
	s := NewState()
	s.Test[0].add("a", now, time.Second)
	s.OK[1].add("b", now, time.Second)
	s.Watch[0].add("c", now, time.Second)
	s.Cooldown[1].add("d", now, time.Second)
	s.Blocks[0].add("1.2.3.0/24", now, time.Second)

	later := now.Add(2 * time.Second)
	s.Expire(later)

	for _, set := range []ttlSet{s.Test[0], s.OK[1], s.Watch[0], s.Cooldown[1], s.Blocks[0]} {
		if len(set) != 0 {
			t.Errorf("set = %v, want empty after Expire", set)
		}
	}
}

func TestProtoIndex(t *testing.T) {
	if protoIndex(false) != 0 {
		t.Error("tcp should be index 0")
	}
	if protoIndex(true) != 1 {
		t.Error("udp should be index 1")
	}
}
