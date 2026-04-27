// SPDX-License-Identifier: Apache-2.0

package types

// ByteShift returns byte(v >> n). Exists so the intentional 8-bit
// truncation used in byte-packing (UUID layout, count-min sketch seeds,
// IPv4 octet formatting, …) is gosec-suppressed in one place rather
// than at every call site.
//
// #nosec G115 -- intentional 8-bit truncation for byte packing
func ByteShift[T ~uint16 | ~uint32 | ~int64](v T, n uint) byte {
	return byte(v >> n)
}
