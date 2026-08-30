package hash

import "encoding/binary"

// md4 implements the RFC 1320 MD4 message digest in ~60 lines of pure Go.
// MD4 is absent from the standard library and long since broken as a security
// primitive, but it is exactly the digest NTLM hashes are built on, so it is
// kept here, local and unexported, solely for the NTLM cracker path.
func md4(data []byte) [16]byte {
	// RFC 1320 padding: 0x80, zeros up to 56 mod 64, then 64-bit bit length.
	bitLen := uint64(len(data)) * 8
	padded := make([]byte, len(data), len(data)+73)
	copy(padded, data)
	padded = append(padded, 0x80)
	for len(padded)%64 != 56 {
		padded = append(padded, 0)
	}
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], bitLen)
	padded = append(padded, lenBuf[:]...)

	h0, h1, h2, h3 := uint32(0x67452301), uint32(0xefcdab89), uint32(0x98badcfe), uint32(0x10325476)

	for i := 0; i < len(padded); i += 64 {
		var x [16]uint32
		for j := 0; j < 16; j++ {
			x[j] = binary.LittleEndian.Uint32(padded[i+j*4:])
		}

		a, b, c, d := h0, h1, h2, h3

		// Round 1: FF, message in order, slots cycle a,d,c,b, shifts 3,7,11,19.
		shift1 := []uint{3, 7, 11, 19}
		for j := 0; j < 16; j++ {
			switch j % 4 {
			case 0:
				a = roll(a+f(b, c, d)+x[j], shift1[j%4])
			case 1:
				d = roll(d+f(a, b, c)+x[j], shift1[j%4])
			case 2:
				c = roll(c+f(d, a, b)+x[j], shift1[j%4])
			case 3:
				b = roll(b+f(c, d, a)+x[j], shift1[j%4])
			}
		}

		// Round 2: GG, message order 0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15,
		// shifts 3,5,9,13, constant 0x5A827999.
		order2 := []int{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
		shift2 := []uint{3, 5, 9, 13}
		for j := 0; j < 16; j++ {
			k := x[order2[j]]
			switch j % 4 {
			case 0:
				a = roll(a+g(b, c, d)+k+0x5a827999, shift2[j%4])
			case 1:
				d = roll(d+g(a, b, c)+k+0x5a827999, shift2[j%4])
			case 2:
				c = roll(c+g(d, a, b)+k+0x5a827999, shift2[j%4])
			case 3:
				b = roll(b+g(c, d, a)+k+0x5a827999, shift2[j%4])
			}
		}

		// Round 3: HH, message order 0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15,
		// shifts 3,9,11,15, constant 0x6ED9EBA1.
		order3 := []int{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}
		shift3 := []uint{3, 9, 11, 15}
		for j := 0; j < 16; j++ {
			k := x[order3[j]]
			switch j % 4 {
			case 0:
				a = roll(a+h(b, c, d)+k+0x6ed9eba1, shift3[j%4])
			case 1:
				d = roll(d+h(a, b, c)+k+0x6ed9eba1, shift3[j%4])
			case 2:
				c = roll(c+h(d, a, b)+k+0x6ed9eba1, shift3[j%4])
			case 3:
				b = roll(b+h(c, d, a)+k+0x6ed9eba1, shift3[j%4])
			}
		}

		h0 += a
		h1 += b
		h2 += c
		h3 += d
	}

	var out [16]byte
	binary.LittleEndian.PutUint32(out[0:4], h0)
	binary.LittleEndian.PutUint32(out[4:8], h1)
	binary.LittleEndian.PutUint32(out[8:12], h2)
	binary.LittleEndian.PutUint32(out[12:16], h3)
	return out
}

// roll rotates v left by n bits.
func roll(v uint32, n uint) uint32 { return (v << n) | (v >> (32 - n)) }

// The three round functions from RFC 1320 section 3.4.
func f(x, y, z uint32) uint32 { return (x & y) | (^x & z) }
func g(x, y, z uint32) uint32 { return (x & y) | (x & z) | (y & z) }
func h(x, y, z uint32) uint32 { return x ^ y ^ z }