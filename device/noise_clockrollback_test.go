/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tai64n"
)

/* TestNoiseHandshakeClockRollback covers the end-to-end clock rollback
 * scenario: the responder recorded a timestamp high-water mark from before
 * the initiator's clock rolled backwards (NTP step, VM snapshot restore),
 * so every new initiation carries a timestamp behind that mark. The new
 * handshakes must be accepted through the recovery path instead of being
 * silently dropped, while genuine replays and stale messages must stay
 * rejected and the high-water mark must never move backwards.
 */
func TestNoiseHandshakeClockRollback(t *testing.T) {
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

	// establish an initial session

	msg1, err := dev1.CreateMessageInitiation(peer2)
	assertNil(t, err)
	if dev2.ConsumeMessageInitiation(msg1) == nil {
		t.Fatal("initial handshake initiation rejected")
	}
	msg2, err := dev2.CreateMessageResponse(peer1)
	assertNil(t, err)
	if dev1.ConsumeMessageResponse(msg2) == nil {
		t.Fatal("initial handshake response rejected")
	}
	assertNil(t, peer1.BeginSymmetricSession())
	assertNil(t, peer2.BeginSymmetricSession())

	// simulate a clock rollback on the initiating side: the responder's
	// recorded high-water mark lies in the future relative to the
	// initiator's corrected clock.

	future := tai64n.FromTime(time.Now().Add(time.Hour))
	peer1.handshake.mutex.Lock()
	peer1.handshake.lastTimestamp = future
	peer1.handshake.lastInitiationConsumption = time.Now().Add(-time.Minute)
	peer1.handshake.mutex.Unlock()

	// the initiator retries a new handshake (RekeyTimeout cadence); every
	// retry carries a timestamp behind the high-water mark and must be
	// accepted rather than silently dropped.

	var msg *MessageInitiation
	for attempt := 0; attempt < 3; attempt++ {
		msg, err = dev1.CreateMessageInitiation(peer2)
		assertNil(t, err)
		if dev2.ConsumeMessageInitiation(msg) == nil {
			t.Fatalf("handshake retry %d after clock rollback was silently dropped", attempt+1)
		}
		// bypass the flood rate limiter between simulated retries
		peer1.handshake.mutex.Lock()
		peer1.handshake.lastInitiationConsumption = time.Now().Add(-time.Minute)
		peer1.handshake.mutex.Unlock()
	}

	// the strictly-increasing high-water mark must not move backwards

	peer1.handshake.mutex.RLock()
	if peer1.handshake.lastTimestamp != future {
		t.Fatal("lastTimestamp high-water mark regressed")
	}
	peer1.handshake.mutex.RUnlock()

	// a byte-identical replay of an accepted initiation must still be
	// dropped as a replay

	if peer := dev2.ConsumeMessageInitiation(msg); peer != nil {
		t.Fatal("replayed initiation was accepted")
	}

	// complete the recovered handshake end to end and pass traffic

	msg2, err = dev2.CreateMessageResponse(peer1)
	assertNil(t, err)
	if dev1.ConsumeMessageResponse(msg2) == nil {
		t.Fatal("handshake response after clock rollback rejected")
	}
	assertNil(t, peer1.BeginSymmetricSession())
	assertNil(t, peer2.BeginSymmetricSession())

	key1 := peer1.keypairs.next.Load()
	key2 := peer2.keypairs.current

	func() {
		testMsg := []byte("wireguard post-rollback message 1")
		var err error
		var out []byte
		var nonce [12]byte
		out = key1.send.Seal(out, nonce[:], testMsg, nil)
		out, err = key2.receive.Open(out[:0], nonce[:], out, nil)
		assertNil(t, err)
		assertEqual(t, out, testMsg)
	}()

	func() {
		testMsg := []byte("wireguard post-rollback message 2")
		var err error
		var out []byte
		var nonce [12]byte
		out = key2.send.Seal(out, nonce[:], testMsg, nil)
		out, err = key1.receive.Open(out[:0], nonce[:], out, nil)
		assertNil(t, err)
		assertEqual(t, out, testMsg)
	}()

	// an initiation whose timestamp is too old to be fresh must still be
	// dropped, even with a brand new ephemeral key

	originalNow := tai64nNow
	tai64nNow = func() tai64n.Timestamp {
		return tai64n.FromTime(time.Now().Add(-time.Hour))
	}
	msgStale, err := dev1.CreateMessageInitiation(peer2)
	tai64nNow = originalNow
	assertNil(t, err)
	if peer := dev2.ConsumeMessageInitiation(msgStale); peer != nil {
		t.Fatal("initiation with timestamp outside the skew window was accepted")
	}
}
