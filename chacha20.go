package chacha20

// sigma is the ChaCha20 constant for 256-bit keys.
var sigma = [16]byte{'e', 'x', 'p', 'a', 'n', 'd', ' ', '3', '2', '-', 'b', 'y', 't', 'e', ' ', 'k'}

// core applies the ChaCha20 core function to 16-byte input in, 32-byte key k,
// and 16-byte constant c, and puts the result into 64-byte array out.
func core(out *[64]byte, in *[16]byte, k *[32]byte, c *[16]byte) {
	j0 := uint32(c[0]) | uint32(c[1])<<8 | uint32(c[2])<<16 | uint32(c[3])<<24
	j1 := uint32(c[4]) | uint32(c[5])<<8 | uint32(c[6])<<16 | uint32(c[7])<<24
	j2 := uint32(c[8]) | uint32(c[9])<<8 | uint32(c[10])<<16 | uint32(c[11])<<24
	j3 := uint32(c[12]) | uint32(c[13])<<8 | uint32(c[14])<<16 | uint32(c[15])<<24
	j4 := uint32(k[0]) | uint32(k[1])<<8 | uint32(k[2])<<16 | uint32(k[3])<<24
	j5 := uint32(k[4]) | uint32(k[5])<<8 | uint32(k[6])<<16 | uint32(k[7])<<24
	j6 := uint32(k[8]) | uint32(k[9])<<8 | uint32(k[10])<<16 | uint32(k[11])<<24
	j7 := uint32(k[12]) | uint32(k[13])<<8 | uint32(k[14])<<16 | uint32(k[15])<<24
	j8 := uint32(k[16]) | uint32(k[17])<<8 | uint32(k[18])<<16 | uint32(k[19])<<24
	j9 := uint32(k[20]) | uint32(k[21])<<8 | uint32(k[22])<<16 | uint32(k[23])<<24
	j10 := uint32(k[24]) | uint32(k[25])<<8 | uint32(k[26])<<16 | uint32(k[27])<<24
	j11 := uint32(k[28]) | uint32(k[29])<<8 | uint32(k[30])<<16 | uint32(k[31])<<24
	j12 := uint32(in[0]) | uint32(in[1])<<8 | uint32(in[2])<<16 | uint32(in[3])<<24
	j13 := uint32(in[4]) | uint32(in[5])<<8 | uint32(in[6])<<16 | uint32(in[7])<<24
	j14 := uint32(in[8]) | uint32(in[9])<<8 | uint32(in[10])<<16 | uint32(in[11])<<24
	j15 := uint32(in[12]) | uint32(in[13])<<8 | uint32(in[14])<<16 | uint32(in[15])<<24

	x0, x1, x2, x3, x4, x5, x6, x7, x8 := j0, j1, j2, j3, j4, j5, j6, j7, j8
	x9, x10, x11, x12, x13, x14, x15 := j9, j10, j11, j12, j13, j14, j15

	for i := 0; i < 20; i += 2 {
		x0 += x4
		x12 ^= x0
		x12 = x12>>(32-16) | x12<<16

		x8 += x12
		x4 ^= x8
		x4 = x4>>(32-12) | x4<<12

		x1 += x5
		x13 ^= x1
		x13 = x13>>(32-16) | x13<<16

		x9 += x13
		x5 ^= x9
		x5 = x5>>(32-12) | x5<<12

		x2 += x6
		x14 ^= x2
		x14 = x14>>(32-16) | x14<<16

		x10 += x14
		x6 ^= x10
		x6 = x6>>(32-12) | x6<<12

		x3 += x7
		x15 ^= x3
		x15 = x15>>(32-16) | x15<<16

		x11 += x15
		x7 ^= x11
		x7 = x7>>(32-12) | x7<<12

		x2 += x6
		x14 ^= x2
		x14 = x14>>(32-8) | x14<<8

		x10 += x14
		x6 ^= x10
		x6 = x6>>(32-7) | x6<<7

		x3 += x7
		x15 ^= x3
		x15 = x15>>(32-8) | x15<<8

		x11 += x15
		x7 ^= x11
		x7 = x7>>(32-7) | x7<<7

		x1 += x5
		x13 ^= x1
		x13 = x13>>(32-8) | x13<<8

		x9 += x13
		x5 ^= x9
		x5 = x5>>(32-7) | x5<<7

		x0 += x4
		x12 ^= x0
		x12 = x12>>(32-8) | x12<<8

		x8 += x12
		x4 ^= x8
		x4 = x4>>(32-7) | x4<<7

		x0 += x5
		x15 ^= x0
		x15 = x15>>(32-16) | x15<<16

		x10 += x15
		x5 ^= x10
		x5 = x5>>(32-12) | x5<<12

		x1 += x6
		x12 ^= x1
		x12 = x12>>(32-16) | x12<<16

		x11 += x12
		x6 ^= x11
		x6 = x6>>(32-12) | x6<<12

		x2 += x7
		x13 ^= x2
		x13 = x13>>(32-16) | x13<<16

		x8 += x13
		x7 ^= x8
		x7 = x7>>(32-12) | x7<<12

		x3 += x4
		x14 ^= x3
		x14 = x14>>(32-16) | x14<<16

		x9 += x14
		x4 ^= x9
		x4 = x4>>(32-12) | x4<<12

		x2 += x7
		x13 ^= x2
		x13 = x13>>(32-8) | x13<<8

		x8 += x13
		x7 ^= x8
		x7 = x7>>(32-7) | x7<<7

		x3 += x4
		x14 ^= x3
		x14 = x14>>(32-8) | x14<<8

		x9 += x14
		x4 ^= x9
		x4 = x4>>(32-7) | x4<<7

		x1 += x6
		x12 ^= x1
		x12 = x12>>(32-8) | x12<<8

		x11 += x12
		x6 ^= x11
		x6 = x6>>(32-7) | x6<<7

		x0 += x5
		x15 ^= x0
		x15 = x15>>(32-8) | x15<<8

		x10 += x15
		x5 ^= x10
		x5 = x5>>(32-7) | x5<<7
	}
	x0 += j0
	x1 += j1
	x2 += j2
	x3 += j3
	x4 += j4
	x5 += j5
	x6 += j6
	x7 += j7
	x8 += j8
	x9 += j9
	x10 += j10
	x11 += j11
	x12 += j12
	x13 += j13
	x14 += j14
	x15 += j15

	out[0] = byte(x0)
	out[1] = byte(x0 >> 8)
	out[2] = byte(x0 >> 16)
	out[3] = byte(x0 >> 24)

	out[4] = byte(x1)
	out[5] = byte(x1 >> 8)
	out[6] = byte(x1 >> 16)
	out[7] = byte(x1 >> 24)

	out[8] = byte(x2)
	out[9] = byte(x2 >> 8)
	out[10] = byte(x2 >> 16)
	out[11] = byte(x2 >> 24)

	out[12] = byte(x3)
	out[13] = byte(x3 >> 8)
	out[14] = byte(x3 >> 16)
	out[15] = byte(x3 >> 24)

	out[16] = byte(x4)
	out[17] = byte(x4 >> 8)
	out[18] = byte(x4 >> 16)
	out[19] = byte(x4 >> 24)

	out[20] = byte(x5)
	out[21] = byte(x5 >> 8)
	out[22] = byte(x5 >> 16)
	out[23] = byte(x5 >> 24)

	out[24] = byte(x6)
	out[25] = byte(x6 >> 8)
	out[26] = byte(x6 >> 16)
	out[27] = byte(x6 >> 24)

	out[28] = byte(x7)
	out[29] = byte(x7 >> 8)
	out[30] = byte(x7 >> 16)
	out[31] = byte(x7 >> 24)

	out[32] = byte(x8)
	out[33] = byte(x8 >> 8)
	out[34] = byte(x8 >> 16)
	out[35] = byte(x8 >> 24)

	out[36] = byte(x9)
	out[37] = byte(x9 >> 8)
	out[38] = byte(x9 >> 16)
	out[39] = byte(x9 >> 24)

	out[40] = byte(x10)
	out[41] = byte(x10 >> 8)
	out[42] = byte(x10 >> 16)
	out[43] = byte(x10 >> 24)

	out[44] = byte(x11)
	out[45] = byte(x11 >> 8)
	out[46] = byte(x11 >> 16)
	out[47] = byte(x11 >> 24)

	out[48] = byte(x12)
	out[49] = byte(x12 >> 8)
	out[50] = byte(x12 >> 16)
	out[51] = byte(x12 >> 24)

	out[52] = byte(x13)
	out[53] = byte(x13 >> 8)
	out[54] = byte(x13 >> 16)
	out[55] = byte(x13 >> 24)

	out[56] = byte(x14)
	out[57] = byte(x14 >> 8)
	out[58] = byte(x14 >> 16)
	out[59] = byte(x14 >> 24)

	out[60] = byte(x15)
	out[61] = byte(x15 >> 8)
	out[62] = byte(x15 >> 16)
	out[63] = byte(x15 >> 24)
}

// XORKeyStream crypts bytes from in to out using the given key and nonce. In
// and out may be the same slice but otherwise should not overlap. Nonce must
// be 8 bytes long.
func XORKeyStream(out, in []byte, nonce []byte, key *[32]byte) {
	if len(out) < len(in) {
		in = in[:len(out)]
	}
	if len(nonce) != 8 {
		panic("chacha20: nonce must be 8 bytes")
	}

	var block [64]byte
	var counter [16]byte
	copy(counter[8:], nonce[:])

	for len(in) >= 64 {
		core(&block, &counter, key, &sigma)
		for i, x := range block {
			out[i] = in[i] ^ x
		}
		u := uint32(1)
		for i := 0; i < 8; i++ {
			u += uint32(counter[i])
			counter[i] = byte(u)
			u >>= 8
		}
		in = in[64:]
		out = out[64:]
	}
	if len(in) > 0 {
		core(&block, &counter, key, &sigma)
		for i, v := range in {
			out[i] = v ^ block[i]
		}
	}
}
