/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/binary"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tai64n"
)

// futureTimestamp returns a tai64n.Timestamp delta ahead of now. It
// simulates the state a responder is left in after the initiator's
// clock stepped backward (NTP step, VM snapshot rollback): the
// responder's recorded timestamp is ahead of any timestamp the
// initiator can produce until its clock catches up.
func futureTimestamp(delta time.Duration) tai64n.Timestamp {
	ts := tai64n.Now()
	binary.BigEndian.PutUint64(ts[:8], binary.BigEndian.Uint64(ts[:8])+uint64(delta/time.Second))
	return ts
}

// TestConsumeMessageInitiationClockStep pins the receiver-side behavior
// of ConsumeMessageInitiation when the peer's clock steps backward:
// a fresh, authenticated initiation with a regressed timestamp must be
// accepted, while an exact replay of an already consumed initiation
// must still be rejected.
func TestConsumeMessageInitiationClockStep(t *testing.T) {
	dev1 := randDevice(t)
	dev2 := randDevice(t)

	defer dev1.Close()
	defer dev2.Close()

	peer1, err := dev2.NewPeer(dev1.staticIdentity.privateKey.publicKey())
	assertNil(t, err)
	peer2, err := dev1.NewPeer(dev2.staticIdentity.privateKey.publicKey())
	assertNil(t, err)
	peer1.Start()
	peer2.Start()

	// clearFlood moves the flood-detection baseline out of the way so
	// the tests below exercise the replay check, not the rate limit.
	clearFlood := func() {
		peer1.handshake.mutex.Lock()
		peer1.handshake.lastInitiationConsumption = time.Now().Add(-time.Second)
		peer1.handshake.mutex.Unlock()
	}

	// A normal initiation is consumed.
	msg1, err := dev1.CreateMessageInitiation(peer2)
	assertNil(t, err)
	if dev2.ConsumeMessageInitiation(msg1) == nil {
		t.Fatal("valid initiation was rejected")
	}

	// The exact same message again is a replay and stays rejected.
	clearFlood()
	if dev2.ConsumeMessageInitiation(msg1) != nil {
		t.Fatal("replayed initiation was accepted")
	}

	// The initiator's clock steps backward: from the responder's point
	// of view its recorded timestamp is now ahead of anything the
	// initiator can produce.
	peer1.handshake.mutex.Lock()
	peer1.handshake.lastTimestamp = futureTimestamp(time.Hour)
	peer1.handshake.mutex.Unlock()

	// A fresh initiation (new ephemeral key, current timestamp) is
	// cryptographically valid, but its timestamp regresses relative to
	// the recorded one. It must be accepted so the tunnel can recover.
	// The sleep spaces the two initiations beyond the tai64n whitener
	// granularity (2^24 ns), so the new initiation gets a distinct
	// timestamp and is not mistaken for an exact replay.
	clearFlood()
	time.Sleep(20 * time.Millisecond)
	msg2, err := dev1.CreateMessageInitiation(peer2)
	assertNil(t, err)
	if dev2.ConsumeMessageInitiation(msg2) == nil {
		t.Fatal("fresh initiation with regressed timestamp was rejected")
	}

	// Its exact replay is still rejected.
	clearFlood()
	if dev2.ConsumeMessageInitiation(msg2) != nil {
		t.Fatal("replayed post-rollback initiation was accepted")
	}
}

// TestHandshakeRecoversAfterClockRollback is the end-to-end regression:
// after the state caused by a clock rollback, a re-initiated handshake
// must complete and the tunnel must carry traffic again.
func TestHandshakeRecoversAfterClockRollback(t *testing.T) {
	goroutineLeakCheck(t)
	pair := genTestPair(t, false)

	// Establish a session.
	pair.Send(t, Ping, nil)

	var initiator, responder *Peer
	for _, p := range pair[0].dev.peers.keyMap {
		initiator = p
	}
	for _, p := range pair[1].dev.peers.keyMap {
		responder = p
	}

	// Simulate the initiator's clock having stepped backward: the
	// responder's last recorded timestamp is now ahead of any
	// timestamp the initiator can produce.
	responder.handshake.mutex.Lock()
	responder.handshake.lastTimestamp = futureTimestamp(time.Hour)
	responder.handshake.mutex.Unlock()

	// Force an immediate re-handshake, bypassing the RekeyTimeout
	// send-rate limit.
	initiator.handshake.mutex.Lock()
	initiator.handshake.lastSentHandshake = time.Now().Add(-2 * RekeyTimeout)
	initiator.handshake.mutex.Unlock()

	completed := initiator.lastHandshakeNano.Load()
	if err := initiator.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("failed to send handshake initiation: %v", err)
	}

	// The responder must accept the regressed-but-authentic initiation
	// and answer it, completing the handshake on the initiator.
	deadline := time.Now().Add(5 * time.Second)
	for initiator.lastHandshakeNano.Load() == completed {
		if time.Now().After(deadline) {
			t.Fatal("handshake did not complete after clock rollback")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The tunnel carries traffic again.
	pair.Send(t, Ping, nil)
	pair.Send(t, Pong, nil)
}

// TestHandshakeRetryExhaustion pins the initiator-side behavior when no
// valid response ever arrives: retries continue at the fixed pace while
// the attempt budget lasts, and once it is exhausted the peer gives up
// and flushes its staged packets instead of retrying forever.
func TestHandshakeRetryExhaustion(t *testing.T) {
	dev := randDevice(t)
	defer dev.Close()

	sk, err := newPrivateKey()
	assertNil(t, err)
	peer, err := dev.NewPeer(sk.publicKey())
	assertNil(t, err)

	// The ChannelTUN delivers an initial EventUp, so the device comes
	// up and starts its peers asynchronously, resetting the attempt
	// counter exactly once. Wait for that to settle so it cannot race
	// the assertions below.
	deadline := time.Now().Add(5 * time.Second)
	for !peer.isRunning.Load() {
		if time.Now().After(deadline) {
			t.Fatal("peer was not started after device came up")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// While the budget remains, the retransmit timer counts and
	// retries.
	peer.timers.handshakeAttempts.Store(0)
	expiredRetransmitHandshake(peer)
	if got := peer.timers.handshakeAttempts.Load(); got != 1 {
		t.Fatalf("expected handshake attempt to be counted, got %d", got)
	}

	// Stage outbound packets waiting for a handshake, then exhaust the
	// attempt budget.
	container := dev.GetOutboundElementsContainer()
	peer.queue.staged <- container
	peer.timers.handshakeAttempts.Store(MaxTimerHandshakes + 1)
	expiredRetransmitHandshake(peer)

	if got := peer.timers.handshakeAttempts.Load(); got != MaxTimerHandshakes+1 {
		t.Fatalf("handshake attempts changed to %d after giving up", got)
	}
	if n := len(peer.queue.staged); n != 0 {
		t.Fatalf("%d staged packet containers not flushed after giving up", n)
	}
}
