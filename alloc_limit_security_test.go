package msgpack

// Security regression tests for the unbounded-allocation DoS (CWE-789/CWE-770).
//
// A MessagePack array/map header declares an element count in as few as 5 bytes
// (e.g. array32 = 0xdd + 4-byte big-endian count, up to ~4.29 billion). The
// decoder must NOT size an allocation directly from that untrusted count.
//
// Each test below gives the decoder a header declaring far more than follows
// it, and checks that what the decoder allocates stays in proportion to the
// data actually supplied rather than to the count in the header.

import (
	"runtime"
	"strconv"
	"testing"
)

// secArray32Header builds a 5-byte array32 header declaring n elements, with NO
// element bytes following it.
func secArray32Header(n uint32) []byte {
	return []byte{0xdd, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

// secBin32Header builds a 5-byte bin32 header declaring n bytes, with none of
// them following it.
func secBin32Header(n uint32) []byte {
	return []byte{0xc6, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

// secStr32Header builds a 5-byte str32 header declaring n bytes, with none of
// them following it. Strings are read into the decoder's own scratch buffer,
// unlike byte slices, which are read into the caller's.
func secStr32Header(n uint32) []byte {
	return []byte{0xdb, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

// secArray16Header builds a 3-byte array16 header declaring n elements.
func secArray16Header(n uint16) []byte {
	return []byte{0xdc, byte(n >> 8), byte(n)}
}

// secMap32Header builds a 5-byte map32 header declaring n entries, with no body.
func secMap32Header(n uint32) []byte {
	return []byte{0xdf, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

func secMeasureAlloc(fn func()) uint64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// secAllocCeiling is the most a decode of a handful of bytes may allocate. It
// sits just above what sliceAllocLimit and maxMapSize cost, so that these tests
// fail both if the bounding is removed and if the limits are raised far enough
// to matter.
const secAllocCeiling = 4 << 20

const secDeclared = 10_000_000 // declared by a 5-byte header

// Test that an array decoded into a typed slice allocates in proportion to the
// elements supplied, not to the count the header declares.
func TestSecAllocBounded_TypedSlice(t *testing.T) {
	data := secArray32Header(secDeclared)
	var dst []int64

	got := secMeasureAlloc(func() { _ = Unmarshal(data, &dst) })

	t.Logf("declared=%d elems, allocated=%.1f MiB (cap=%d elems)",
		secDeclared, float64(got)/(1<<20), int(sliceAllocLimit))
	if got > secAllocCeiling {
		t.Fatalf("typed slice allocation not bounded: a %d-byte header allocated %d bytes (> %d). "+
			"sliceAllocLimit bypassed (CWE-789).", len(data), got, secAllocCeiling)
	}
}

// Test the same for an array decoded into an interface{}, which the decoder
// reaches by a different path than a typed slice.
func TestSecAllocBounded_InterfaceSlice(t *testing.T) {
	data := secArray32Header(secDeclared)
	var dst interface{}

	got := secMeasureAlloc(func() { _ = Unmarshal(data, &dst) })

	t.Logf("declared=%d elems, allocated=%.1f MiB", secDeclared, float64(got)/(1<<20))
	if got > secAllocCeiling {
		t.Fatalf("interface{} allocation not bounded: allocated %d bytes (> %d)", got, secAllocCeiling)
	}
}

// Test the same for a map, which is allocated once at its declared size rather
// than grown an element at a time.
func TestSecAllocBounded_Map(t *testing.T) {
	data := secMap32Header(secDeclared)
	var dst map[string]interface{}

	got := secMeasureAlloc(func() { _ = Unmarshal(data, &dst) })

	// a map is allowed more than secAllocCeiling because Go sizes map
	// buckets generously, at roughly 80 bytes an entry against 16 for a
	// slice element
	const mapCeiling = 16 << 20
	t.Logf("declared=%d entries, allocated=%.1f MiB (cap=%d)",
		secDeclared, float64(got)/(1<<20), int(maxMapSize))
	if got > mapCeiling {
		t.Fatalf("map allocation not bounded: allocated %d bytes (> %d)", got, mapCeiling)
	}
}

// Test that a slice with more elements than the limit still decodes in full,
// so that bounding what is allocated up front has not capped the result.
func TestSecHonestLargeSliceRoundTrips(t *testing.T) {
	const n = 1_500_000 // more than sliceAllocLimit

	in := make([]int64, n)
	for i := range in {
		in[i] = int64(i)
	}

	b, err := Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out []int64
	if err := Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(out) != n {
		t.Fatalf("length mismatch: got %d, want %d", len(out), n)
	}
	if out[0] != 0 || out[n-1] != int64(n-1) {
		t.Fatalf("value mismatch: out[0]=%d out[%d]=%d", out[0], n-1, out[n-1])
	}
}

// Test that a map with more entries than the limit still decodes in full.
func TestSecHonestLargeMapRoundTrips(t *testing.T) {
	const n = 200_000 // more than maxMapSize

	in := make(map[string]int64, n)
	for i := 0; i < n; i++ {
		in[strconv.Itoa(i)] = int64(i)
	}

	b, err := Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out map[string]int64
	if err := Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(out) != n {
		t.Fatalf("length mismatch: got %d, want %d", len(out), n)
	}
	if out["0"] != 0 || out[strconv.Itoa(n-1)] != int64(n-1) {
		t.Fatalf("value mismatch: out[0]=%d out[%d]=%d", out["0"], n-1, out[strconv.Itoa(n-1)])
	}
}

// Test that a bin header declaring far more bytes than follow it does not
// allocate the length it declares, whether the destination is a []byte or an
// interface{}.
func TestSecAllocBounded_Bytes(t *testing.T) {
	const declared = 808_464_432

	data := secBin32Header(declared)

	for _, tc := range []struct {
		name string
		dst  interface{}
	}{
		{"[]byte", new([]byte)},
		{"interface{}", new(interface{})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := secMeasureAlloc(func() { _ = Unmarshal(data, tc.dst) })

			t.Logf("declared=%d bytes, allocated=%.1f MiB (step=%d)",
				declared, float64(got)/(1<<20), bytesAllocLimit)
			if got > secAllocCeiling {
				t.Fatalf("byte slice allocation not bounded: a %d-byte header allocated %d bytes (> %d)",
					len(data), got, secAllocCeiling)
			}
		})
	}
}

// Test that a byte slice longer than bytesAllocLimit still decodes in full,
// now that it is assembled a step at a time.
func TestSecHonestLargeBytesRoundTrip(t *testing.T) {
	in := make([]byte, 3*bytesAllocLimit+17)
	for i := range in {
		in[i] = byte(i)
	}

	b, err := Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out []byte
	if err := Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(out) != len(in) {
		t.Fatalf("length mismatch: got %d, want %d", len(out), len(in))
	}
	for i := range in {
		if out[i] != in[i] {
			t.Fatalf("value mismatch at %d: got %d, want %d", i, out[i], in[i])
		}
	}
}

// Test that decoding the same oversized length over and over costs the same
// each time. Decoders are pooled, and a decode that fails partway keeps the
// buffer it grew, so unless PutDecoder discards an oversized one the cost of
// each decode climbs as the pool warms up.
func TestSecPooledBufferDoesNotRatchet(t *testing.T) {
	// a str, so that the read goes through the decoder's pooled scratch
	// buffer rather than a slice the caller owns
	data := secStr32Header(808_464_432)

	var first, last uint64
	for i := 0; i < 200; i++ {
		var dst string
		got := secMeasureAlloc(func() { _ = Unmarshal(data, &dst) })
		if i == 0 {
			first = got
		}
		last = got

		if got > secAllocCeiling {
			t.Fatalf("decode %d allocated %d bytes (> %d): the pooled scratch buffer is growing between decodes",
				i, got, secAllocCeiling)
		}
	}

	t.Logf("first=%.2f MiB last=%.2f MiB", float64(first)/(1<<20), float64(last)/(1<<20))
}

// Test that a body of nothing but nested array headers stays bounded. A limit
// on each collection does not bound their total, because every level allocates
// its own and a three-byte header can declare 65535 elements while sitting
// under any useful limit.
func TestSecAllocBounded_NestedArrays(t *testing.T) {
	const depth = 64

	var data []byte
	for i := 0; i < depth; i++ {
		data = append(data, secArray16Header(65535)...)
	}

	var dst interface{}
	got := secMeasureAlloc(func() { _ = Unmarshal(data, &dst) })

	t.Logf("depth=%d in %d bytes, allocated=%.2f MiB", depth, len(data), float64(got)/(1<<20))
	if got > secAllocCeiling {
		t.Fatalf("nested allocation not bounded: %d bytes of headers allocated %d bytes (> %d)",
			len(data), got, secAllocCeiling)
	}
}

// Test the same for a much longer run of nested array headers. Clipping each
// collection to the input left is not enough on its own, because every level
// is clipped against much the same input as the one above it, so the total
// still grows with the square of the body.
func TestSecAllocBounded_DeeplyNestedArrays(t *testing.T) {
	data := []byte{0x9d, 0x00}
	for i := 0; i < 2456; i++ {
		data = append(data, 0xdc)
	}

	var dst interface{}
	got := secMeasureAlloc(func() { _ = Unmarshal(data, &dst) })

	t.Logf("%d bytes of headers, allocated=%.2f MiB", len(data), float64(got)/(1<<20))
	if got > secAllocCeiling {
		t.Fatalf("nested allocation not bounded: %d bytes allocated %d bytes (> %d)",
			len(data), got, secAllocCeiling)
	}
}

// Test that a wide structure, which spends from the same budget a deep nest
// would, still decodes in full. It has to: every element costs at least a byte
// to encode, so a body can never hold more elements than the budget allows.
func TestSecHonestWideStructureRoundTrips(t *testing.T) {
	in := make([]map[string]int, 2000)
	for i := range in {
		in[i] = map[string]int{"a": i, "b": i * 2, "c": i * 3}
	}

	b, err := Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out []map[string]int
	if err := Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(out) != len(in) {
		t.Fatalf("length mismatch: got %d, want %d", len(out), len(in))
	}
	for i := range in {
		if len(out[i]) != 3 || out[i]["b"] != i*2 {
			t.Fatalf("entry %d wrong: %v", i, out[i])
		}
	}
}

// Test that input nested deeper than the decoder will follow is rejected
// rather than followed. Each level of nesting is a level of recursion, so
// without a limit a body of nothing but one-byte array headers grows the
// goroutine stack until it passes the 1gb a goroutine may have, which is a
// fatal error that no recover can catch.
func TestSecNestingDepthIsBounded(t *testing.T) {
	// a couple of megabytes of headers, which is enough to exhaust the
	// stack but small enough to be an unremarkable request body
	data := make([]byte, 2_785_280)
	for i := range data {
		data[i] = 0x91 // fixarray of one element: one byte, one level
	}

	for _, tc := range []struct {
		name string
		dst  func() interface{}
	}{
		{"interface{}", func() interface{} { return new(interface{}) }},
		{"[]interface{}", func() interface{} { return new([]interface{}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Unmarshal(data, tc.dst())
			if err == nil {
				t.Fatal("expected an error, got none")
			}
			t.Logf("%v", err)
		})
	}
}

// Test that nesting a struct decodes to the same depth, since struct fields
// reach their values by a different route than slice and map elements do.
func TestSecNestingDepthIsBoundedThroughStructs(t *testing.T) {
	type node struct {
		Next interface{} `msgpack:"n"`
	}

	// {"n": {"n": {"n": ...}}}, one fixmap and one one-byte key per level
	var data []byte
	for i := 0; i < maxDepth+1000; i++ {
		data = append(data, 0x81, 0xa1, 'n')
	}
	data = append(data, 0xc0)

	if err := Unmarshal(data, new(node)); err == nil {
		t.Fatal("expected an error, got none")
	}
}

// Test that nesting well within the limit still decodes, so that the limit has
// not been set somewhere a real payload would reach.
func TestSecNestingWithinDepthDecodes(t *testing.T) {
	const depth = 100

	in := interface{}("leaf")
	for i := 0; i < depth; i++ {
		in = []interface{}{in}
	}

	b, err := Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out interface{}
	if err := Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for i := 0; i < depth; i++ {
		s, ok := out.([]interface{})
		if !ok || len(s) != 1 {
			t.Fatalf("level %d: expected a one-element slice, got %#v", i, out)
		}
		out = s[0]
	}
	if out != "leaf" {
		t.Fatalf("expected the leaf, got %#v", out)
	}
}

// Test that a value nested inside a CustomDecoder does not get a fresh
// allocation allowance. A CustomDecoder is handed the same Decoder and may
// call Decode again for a field, which must not refill the budget, or a value
// nested inside enough of them could allocate without limit.
func TestSecCustomDecoderDoesNotRefillBudget(t *testing.T) {
	data := secArray32Header(secDeclared)

	var direct, nested uint64
	func() {
		var dst []int64
		direct = secMeasureAlloc(func() { _ = Unmarshal(data, &dst) })
	}()
	func() {
		var dst secNestingCustom
		nested = secMeasureAlloc(func() { _ = Unmarshal(data, &dst) })
	}()

	t.Logf("direct=%d bytes, through a CustomDecoder=%d bytes", direct, nested)
	if nested > secAllocCeiling {
		t.Fatalf("allocation through a CustomDecoder not bounded: %d bytes (> %d)",
			nested, secAllocCeiling)
	}
}

// secNestingCustom decodes by calling back into Decode, as a CustomDecoder may.
type secNestingCustom struct {
	values []int64
}

func (c *secNestingCustom) DecodeMsgpack(d *Decoder) error {
	return d.Decode(&c.values)
}
