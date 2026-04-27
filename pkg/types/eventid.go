// SPDX-License-Identifier: Apache-2.0

package types

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"time"
)

// UUIDv7 generates a time-ordered 128-bit identifier as a 36-char hyphenated
// hex string. Format follows RFC 9562 §5.7: 48-bit unix ms timestamp | 4-bit
// version (7) | 12-bit rand_a | 2-bit variant (10) | 62-bit rand_b.
// Monotonicity within the same millisecond is enforced via a per-process
// 12-bit counter in rand_a.
func UUIDv7() string {
	return uuidGen.next()
}

type uuidv7Gen struct {
	mu        sync.Mutex
	lastMS    int64
	lastRandA uint16
}

var uuidGen uuidv7Gen

func (g *uuidv7Gen) next() string {
	now := time.Now().UnixMilli()

	g.mu.Lock()
	if now <= g.lastMS {
		// Either same ms or clock skew: keep lastMS and advance the counter.
		next := (g.lastRandA + 1) & 0x0FFF
		if next == 0 {
			// Counter wrapped — borrow from the next millisecond to stay monotonic.
			g.lastMS++
			// Reseed randA fresh so following calls within the new virtual ms don't
			// artificially collide with a future real timestamp.
			var b [2]byte
			_, _ = rand.Read(b[:])
			next = binary.BigEndian.Uint16(b[:]) & 0x0FFF
		}
		g.lastRandA = next
	} else {
		g.lastMS = now
		var b [2]byte
		_, _ = rand.Read(b[:])
		g.lastRandA = binary.BigEndian.Uint16(b[:]) & 0x0FFF
	}
	ms := g.lastMS
	randA := g.lastRandA
	g.mu.Unlock()

	var randB [8]byte
	_, _ = rand.Read(randB[:])

	var out [16]byte
	// 48-bit timestamp, byte-packed MSB-first.
	out[0] = ByteShift(ms, 40)
	out[1] = ByteShift(ms, 32)
	out[2] = ByteShift(ms, 24)
	out[3] = ByteShift(ms, 16)
	out[4] = ByteShift(ms, 8)
	out[5] = ByteShift(ms, 0)
	// version (7) | rand_a high nibble
	out[6] = 0x70 | ByteShift(randA, 8)&0x0F
	out[7] = ByteShift(randA, 0)
	// variant (10) | rand_b
	out[8] = 0x80 | (randB[0] & 0x3F)
	out[9] = randB[1]
	out[10] = randB[2]
	out[11] = randB[3]
	out[12] = randB[4]
	out[13] = randB[5]
	out[14] = randB[6]
	out[15] = randB[7]

	// Format 8-4-4-4-12
	buf := make([]byte, 36)
	hex.Encode(buf[0:8], out[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], out[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], out[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], out[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], out[10:16])
	return string(buf)
}
