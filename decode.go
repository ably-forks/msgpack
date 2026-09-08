package msgpack

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"

	"github.com/vmihailenco/msgpack/v5/msgpcode"
)

const (
	bytesAllocLimit = 1 << 20 // 1mb
	sliceAllocLimit = 1 << 16 // 64k elements
	maxMapSize      = 1 << 12 // 4k elements
)

// The slice and map limits above cap how many elements are allocated up front
// from a length the stream declares but has not yet supplied. Anything longer
// still decodes, growing through append and map assignment as the elements
// arrive, so the limits only have to keep the common case from reallocating.
//
// The map limit is the lower of the two because a map entry costs much more
// memory than a slice element: around 80 bytes once Go has sized its buckets,
// against 16 bytes for an element of a []interface{}.

const (
	looseInterfaceDecodingFlag uint32 = 1 << iota
	disallowUnknownFieldsFlag
	usePreallocateValues
	disableAllocLimitFlag
)

type bufReader interface {
	io.Reader
	io.ByteScanner
}

//------------------------------------------------------------------------------

var decPool = sync.Pool{
	New: func() interface{} {
		return NewDecoder(nil)
	},
}

func GetDecoder() *Decoder {
	return decPool.Get().(*Decoder)
}

func PutDecoder(dec *Decoder) {
	dec.r = nil
	dec.s = nil

	// A decode that fails partway keeps the buffer it grew towards the
	// declared length, so discard an oversized one rather than leave it in
	// the pool for the next decode to grow further still.
	if cap(dec.buf) > bytesAllocLimit {
		dec.buf = nil
	}

	decPool.Put(dec)
}

//------------------------------------------------------------------------------

// Unmarshal decodes the MessagePack-encoded data and stores the result
// in the value pointed to by v.
func Unmarshal(data []byte, v interface{}) error {
	dec := GetDecoder()
	dec.UsePreallocateValues(true)
	dec.Reset(bytes.NewReader(data))
	err := dec.Decode(v)

	PutDecoder(dec)

	return err
}

// A Decoder reads and decodes MessagePack values from an input stream.
type Decoder struct {
	r          io.Reader
	s          io.ByteScanner
	mapDecoder func(*Decoder) (interface{}, error)

	// If the reader can report how much input is left, one of these holds
	// it: a bytes.Reader, bytes.Buffer or strings.Reader through Len, a
	// bufio.Reader through Buffered. At most one is ever set, and initLen
	// uses whichever it is. They are interfaces rather than bound methods
	// because binding a method allocates.
	lenr interface{ Len() int }
	bufr interface{ Buffered() int }

	// budget is how many more elements may be allocated ahead of the data
	// for them, for this decode. See initLen.
	budget int

	// depth is how many levels of nesting are currently being decoded.
	// See enter.
	depth     int
	structTag string
	buf       []byte
	rec       []byte
	dict      []string
	flags     uint32
}

// NewDecoder returns a new decoder that reads from r.
//
// The decoder introduces its own buffering and may read data from r
// beyond the requested msgpack values. Buffering can be disabled
// by passing a reader that implements io.ByteScanner interface.
func NewDecoder(r io.Reader) *Decoder {
	d := new(Decoder)
	d.Reset(r)
	return d
}

// Reset discards any buffered data, resets all state, and switches the buffered
// reader to read from r.
func (d *Decoder) Reset(r io.Reader) {
	d.ResetDict(r, nil)
}

// ResetDict is like Reset, but also resets the dict.
func (d *Decoder) ResetDict(r io.Reader, dict []string) {
	d.ResetReader(r)
	d.flags = 0
	d.structTag = ""
	d.dict = dict
}

func (d *Decoder) WithDict(dict []string, fn func(*Decoder) error) error {
	oldDict := d.dict
	d.dict = dict
	err := fn(d)
	d.dict = oldDict
	return err
}

func (d *Decoder) ResetReader(r io.Reader) {
	d.mapDecoder = nil
	d.dict = nil

	if br, ok := r.(bufReader); ok {
		d.r = br
		d.s = br
	} else if r == nil {
		d.r = nil
		d.s = nil
	} else {
		br := bufio.NewReader(r)
		d.r = br
		d.s = br
	}

	// Work out once, rather than on every collection decoded, which method
	// reports how much input is left. Len is exact, and is what Unmarshal
	// ends up using; Buffered counts only what has been read ahead, so it
	// is a lower bound, which initLen is still safe to clip against.
	d.budget = -1
	d.depth = 0
	d.lenr, d.bufr = nil, nil
	switch rr := d.r.(type) {
	case interface{ Len() int }:
		d.lenr = rr
	case interface{ Buffered() int }:
		d.bufr = rr
	}
}

func (d *Decoder) SetMapDecoder(fn func(*Decoder) (interface{}, error)) {
	d.mapDecoder = fn
}

// UseLooseInterfaceDecoding causes decoder to use DecodeInterfaceLoose
// to decode msgpack value into Go interface{}.
func (d *Decoder) UseLooseInterfaceDecoding(on bool) {
	if on {
		d.flags |= looseInterfaceDecodingFlag
	} else {
		d.flags &= ^looseInterfaceDecodingFlag
	}
}

// SetCustomStructTag causes the decoder to use the supplied tag as a fallback option
// if there is no msgpack tag.
func (d *Decoder) SetCustomStructTag(tag string) {
	d.structTag = tag
}

// DisallowUnknownFields causes the Decoder to return an error when the destination
// is a struct and the input contains object keys which do not match any
// non-ignored, exported fields in the destination.
func (d *Decoder) DisallowUnknownFields(on bool) {
	if on {
		d.flags |= disallowUnknownFieldsFlag
	} else {
		d.flags &= ^disallowUnknownFieldsFlag
	}
}

// UseInternedStrings enables support for decoding interned strings.
func (d *Decoder) UseInternedStrings(on bool) {
	if on {
		d.flags |= useInternedStringsFlag
	} else {
		d.flags &= ^useInternedStringsFlag
	}
}

// UsePreallocateValues enables preallocating values in chunks
func (d *Decoder) UsePreallocateValues(on bool) {
	if on {
		d.flags |= usePreallocateValues
	} else {
		d.flags &= ^usePreallocateValues
	}
}

// DisableAllocLimit enables fully allocating slices/maps when the size is known
func (d *Decoder) DisableAllocLimit(on bool) {
	if on {
		d.flags |= disableAllocLimitFlag
	} else {
		d.flags &= ^disableAllocLimitFlag
	}
}

// Buffered returns a reader of the data remaining in the Decoder's buffer.
// The reader is valid until the next call to Decode.
func (d *Decoder) Buffered() io.Reader {
	return d.r
}

//nolint:gocyclo
func (d *Decoder) Decode(v interface{}) error {
	// Each value gets its own allowance; see initLen. Only the outermost
	// decode, though: a CustomDecoder is handed the same Decoder and may
	// call back into Decode for a field, and refilling there would let a
	// value nested inside enough of them allocate without limit.
	if d.depth == 0 {
		d.budget = -1
	}

	var err error
	switch v := v.(type) {
	case *string:
		if v != nil {
			*v, err = d.DecodeString()
			return err
		}
	case *[]byte:
		if v != nil {
			return d.decodeBytesPtr(v)
		}
	case *int:
		if v != nil {
			*v, err = d.DecodeInt()
			return err
		}
	case *int8:
		if v != nil {
			*v, err = d.DecodeInt8()
			return err
		}
	case *int16:
		if v != nil {
			*v, err = d.DecodeInt16()
			return err
		}
	case *int32:
		if v != nil {
			*v, err = d.DecodeInt32()
			return err
		}
	case *int64:
		if v != nil {
			*v, err = d.DecodeInt64()
			return err
		}
	case *uint:
		if v != nil {
			*v, err = d.DecodeUint()
			return err
		}
	case *uint8:
		if v != nil {
			*v, err = d.DecodeUint8()
			return err
		}
	case *uint16:
		if v != nil {
			*v, err = d.DecodeUint16()
			return err
		}
	case *uint32:
		if v != nil {
			*v, err = d.DecodeUint32()
			return err
		}
	case *uint64:
		if v != nil {
			*v, err = d.DecodeUint64()
			return err
		}
	case *bool:
		if v != nil {
			*v, err = d.DecodeBool()
			return err
		}
	case *float32:
		if v != nil {
			*v, err = d.DecodeFloat32()
			return err
		}
	case *float64:
		if v != nil {
			*v, err = d.DecodeFloat64()
			return err
		}
	case *[]string:
		return d.decodeStringSlicePtr(v)
	case *map[string]string:
		return d.decodeMapStringStringPtr(v)
	case *map[string]interface{}:
		return d.decodeMapStringInterfacePtr(v)
	case *time.Duration:
		if v != nil {
			vv, err := d.DecodeInt64()
			*v = time.Duration(vv)
			return err
		}
	case *time.Time:
		if v != nil {
			*v, err = d.DecodeTime()
			return err
		}
	}

	vv := reflect.ValueOf(v)
	if !vv.IsValid() {
		return errors.New("msgpack: Decode(nil)")
	}
	if vv.Kind() != reflect.Ptr {
		return fmt.Errorf("msgpack: Decode(non-pointer %T)", v)
	}
	if vv.IsNil() {
		return fmt.Errorf("msgpack: Decode(non-settable %T)", v)
	}

	vv = vv.Elem()
	if vv.Kind() == reflect.Interface {
		if !vv.IsNil() {
			vv = vv.Elem()
			if vv.Kind() != reflect.Ptr {
				return fmt.Errorf("msgpack: Decode(non-pointer %s)", vv.Type().String())
			}
		}
	}

	return d.DecodeValue(vv)
}

func (d *Decoder) DecodeMulti(v ...interface{}) error {
	for _, vv := range v {
		if err := d.Decode(vv); err != nil {
			return err
		}
	}
	return nil
}

func (d *Decoder) decodeInterfaceCond() (interface{}, error) {
	if err := d.enter(); err != nil {
		return nil, err
	}

	var (
		v   interface{}
		err error
	)
	if d.flags&looseInterfaceDecodingFlag != 0 {
		v, err = d.DecodeInterfaceLoose()
	} else {
		v, err = d.DecodeInterface()
	}

	d.leave()
	return v, err
}

func (d *Decoder) DecodeValue(v reflect.Value) error {
	if err := d.enter(); err != nil {
		return err
	}

	decode := getDecoder(v.Type())
	err := decode(d, v)

	d.leave()
	return err
}

func (d *Decoder) DecodeNil() error {
	c, err := d.readCode()
	if err != nil {
		return err
	}
	if c != msgpcode.Nil {
		return fmt.Errorf("msgpack: invalid code=%x decoding nil", c)
	}
	return nil
}

func (d *Decoder) decodeNilValue(v reflect.Value) error {
	err := d.DecodeNil()
	if v.IsNil() {
		return err
	}
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	v.Set(reflect.Zero(v.Type()))
	return err
}

func (d *Decoder) DecodeBool() (bool, error) {
	c, err := d.readCode()
	if err != nil {
		return false, err
	}
	return d.bool(c)
}

func (d *Decoder) bool(c byte) (bool, error) {
	if c == msgpcode.Nil {
		return false, nil
	}
	if c == msgpcode.False {
		return false, nil
	}
	if c == msgpcode.True {
		return true, nil
	}
	return false, fmt.Errorf("msgpack: invalid code=%x decoding bool", c)
}

func (d *Decoder) DecodeDuration() (time.Duration, error) {
	n, err := d.DecodeInt64()
	if err != nil {
		return 0, err
	}
	return time.Duration(n), nil
}

// DecodeInterface decodes value into interface. It returns following types:
//   - nil,
//   - bool,
//   - int8, int16, int32, int64,
//   - uint8, uint16, uint32, uint64,
//   - float32 and float64,
//   - string,
//   - []byte,
//   - slices of any of the above,
//   - maps of any of the above.
//
// DecodeInterface should be used only when you don't know the type of value
// you are decoding. For example, if you are decoding number it is better to use
// DecodeInt64 for negative numbers and DecodeUint64 for positive numbers.
func (d *Decoder) DecodeInterface() (interface{}, error) {
	c, err := d.readCode()
	if err != nil {
		return nil, err
	}

	if msgpcode.IsFixedNum(c) {
		return int8(c), nil
	}
	if msgpcode.IsFixedMap(c) {
		err = d.s.UnreadByte()
		if err != nil {
			return nil, err
		}
		return d.decodeMapDefault()
	}
	if msgpcode.IsFixedArray(c) {
		return d.decodeSlice(c)
	}
	if msgpcode.IsFixedString(c) {
		return d.string(c)
	}

	switch c {
	case msgpcode.Nil:
		return nil, nil
	case msgpcode.False, msgpcode.True:
		return d.bool(c)
	case msgpcode.Float:
		return d.float32(c)
	case msgpcode.Double:
		return d.float64(c)
	case msgpcode.Uint8:
		return d.uint8()
	case msgpcode.Uint16:
		return d.uint16()
	case msgpcode.Uint32:
		return d.uint32()
	case msgpcode.Uint64:
		return d.uint64()
	case msgpcode.Int8:
		return d.int8()
	case msgpcode.Int16:
		return d.int16()
	case msgpcode.Int32:
		return d.int32()
	case msgpcode.Int64:
		return d.int64()
	case msgpcode.Bin8, msgpcode.Bin16, msgpcode.Bin32:
		return d.bytes(c, nil)
	case msgpcode.Str8, msgpcode.Str16, msgpcode.Str32:
		return d.string(c)
	case msgpcode.Array16, msgpcode.Array32:
		return d.decodeSlice(c)
	case msgpcode.Map16, msgpcode.Map32:
		err = d.s.UnreadByte()
		if err != nil {
			return nil, err
		}
		return d.decodeMapDefault()
	case msgpcode.FixExt1, msgpcode.FixExt2, msgpcode.FixExt4, msgpcode.FixExt8, msgpcode.FixExt16,
		msgpcode.Ext8, msgpcode.Ext16, msgpcode.Ext32:
		return d.decodeInterfaceExt(c)
	}

	return 0, fmt.Errorf("msgpack: unknown code %x decoding interface{}", c)
}

// DecodeInterfaceLoose is like DecodeInterface except that:
//   - int8, int16, and int32 are converted to int64,
//   - uint8, uint16, and uint32 are converted to uint64,
//   - float32 is converted to float64.
//   - []byte is converted to string.
func (d *Decoder) DecodeInterfaceLoose() (interface{}, error) {
	c, err := d.readCode()
	if err != nil {
		return nil, err
	}

	if msgpcode.IsFixedNum(c) {
		return int64(int8(c)), nil
	}
	if msgpcode.IsFixedMap(c) {
		err = d.s.UnreadByte()
		if err != nil {
			return nil, err
		}
		return d.decodeMapDefault()
	}
	if msgpcode.IsFixedArray(c) {
		return d.decodeSlice(c)
	}
	if msgpcode.IsFixedString(c) {
		return d.string(c)
	}

	switch c {
	case msgpcode.Nil:
		return nil, nil
	case msgpcode.False, msgpcode.True:
		return d.bool(c)
	case msgpcode.Float, msgpcode.Double:
		return d.float64(c)
	case msgpcode.Uint8, msgpcode.Uint16, msgpcode.Uint32, msgpcode.Uint64:
		return d.uint(c)
	case msgpcode.Int8, msgpcode.Int16, msgpcode.Int32, msgpcode.Int64:
		return d.int(c)
	case msgpcode.Str8, msgpcode.Str16, msgpcode.Str32,
		msgpcode.Bin8, msgpcode.Bin16, msgpcode.Bin32:
		return d.string(c)
	case msgpcode.Array16, msgpcode.Array32:
		return d.decodeSlice(c)
	case msgpcode.Map16, msgpcode.Map32:
		err = d.s.UnreadByte()
		if err != nil {
			return nil, err
		}
		return d.decodeMapDefault()
	case msgpcode.FixExt1, msgpcode.FixExt2, msgpcode.FixExt4, msgpcode.FixExt8, msgpcode.FixExt16,
		msgpcode.Ext8, msgpcode.Ext16, msgpcode.Ext32:
		return d.decodeInterfaceExt(c)
	}

	return 0, fmt.Errorf("msgpack: unknown code %x decoding interface{}", c)
}

// Skip skips next value.
func (d *Decoder) Skip() error {
	c, err := d.readCode()
	if err != nil {
		return err
	}

	if msgpcode.IsFixedNum(c) {
		return nil
	}
	if msgpcode.IsFixedMap(c) {
		return d.skipMap(c)
	}
	if msgpcode.IsFixedArray(c) {
		return d.skipSlice(c)
	}
	if msgpcode.IsFixedString(c) {
		return d.skipBytes(c)
	}

	switch c {
	case msgpcode.Nil, msgpcode.False, msgpcode.True:
		return nil
	case msgpcode.Uint8, msgpcode.Int8:
		return d.skipN(1)
	case msgpcode.Uint16, msgpcode.Int16:
		return d.skipN(2)
	case msgpcode.Uint32, msgpcode.Int32, msgpcode.Float:
		return d.skipN(4)
	case msgpcode.Uint64, msgpcode.Int64, msgpcode.Double:
		return d.skipN(8)
	case msgpcode.Bin8, msgpcode.Bin16, msgpcode.Bin32:
		return d.skipBytes(c)
	case msgpcode.Str8, msgpcode.Str16, msgpcode.Str32:
		return d.skipBytes(c)
	case msgpcode.Array16, msgpcode.Array32:
		return d.skipSlice(c)
	case msgpcode.Map16, msgpcode.Map32:
		return d.skipMap(c)
	case msgpcode.FixExt1, msgpcode.FixExt2, msgpcode.FixExt4, msgpcode.FixExt8, msgpcode.FixExt16,
		msgpcode.Ext8, msgpcode.Ext16, msgpcode.Ext32:
		return d.skipExt(c)
	}

	return fmt.Errorf("msgpack: unknown code %x", c)
}

func (d *Decoder) DecodeRaw() (RawMessage, error) {
	d.rec = make([]byte, 0)
	if err := d.Skip(); err != nil {
		return nil, err
	}
	msg := RawMessage(d.rec)
	d.rec = nil
	return msg, nil
}

// PeekCode returns the next MessagePack code without advancing the reader.
// Subpackage msgpack/codes defines the list of available msgpcode.
func (d *Decoder) PeekCode() (byte, error) {
	c, err := d.s.ReadByte()
	if err != nil {
		return 0, err
	}
	return c, d.s.UnreadByte()
}

// ReadFull reads exactly len(buf) bytes into the buf.
func (d *Decoder) ReadFull(buf []byte) error {
	_, err := readN(d.r, buf, len(buf))
	return err
}

func (d *Decoder) hasNilCode() bool {
	code, err := d.PeekCode()
	return err == nil && code == msgpcode.Nil
}

func (d *Decoder) readCode() (byte, error) {
	c, err := d.s.ReadByte()
	if err != nil {
		return 0, err
	}
	if d.rec != nil {
		d.rec = append(d.rec, c)
	}
	return c, nil
}

func (d *Decoder) readFull(b []byte) error {
	_, err := io.ReadFull(d.r, b)
	if err != nil {
		return err
	}
	if d.rec != nil {
		d.rec = append(d.rec, b...)
	}
	return nil
}

func (d *Decoder) readN(n int) ([]byte, error) {
	var err error
	if d.flags&disableAllocLimitFlag != 0 {
		d.buf, err = readN(d.r, d.buf, n)
	} else {
		d.buf, err = readNGrow(d.r, d.buf, n)
	}
	if err != nil {
		return nil, err
	}
	if d.rec != nil {
		// TODO: read directly into d.rec?
		d.rec = append(d.rec, d.buf...)
	}
	return d.buf, nil
}

// initLen returns how many elements of a collection to allocate up front,
// given that the stream has declared n of them.
//
// n is declared by the input and not yet backed by any of it, so it is clipped
// two ways: to limit, and to as many elements as the input still to come could
// possibly hold, at minBytesPerElem bytes each.
//
// The second clip is what starts to bound nesting. A limit alone does not: a
// three-byte array16 header can declare 65535 elements, which sits under any
// useful limit, and a body full of them nests so that every level allocates
// its own. 192 bytes of headers reached 64mb that way.
//
// Clipping is always safe. This is only how much is allocated before the
// elements arrive; append and map assignment grow to fit however many actually
// do, so a clip that turns out to be low costs a reallocation and nothing else.
func (d *Decoder) initLen(n, limit, minBytesPerElem int) int {
	if d.flags&disableAllocLimitFlag != 0 {
		return n
	}
	if n > limit {
		n = limit
	}

	avail := d.bytesAvailable()
	if avail >= 0 {
		// keep a floor, so that a reader which happens to have little
		// buffered does not cost every small collection a reallocation
		if max := max(avail/minBytesPerElem, minInitLen); n > max {
			n = max
		}

		// Clipping each collection to the input left still lets nesting
		// add them up, since every level is clipped against much the
		// same input as the one above it: 2.4kb of array16 headers
		// reached 17mb that way, growing with the square of the body.
		//
		// So also spend from a budget for the whole decode. Every
		// element costs at least a byte to encode, so a valid input of
		// n bytes holds at most n elements however they are arranged,
		// which makes the input left an allowance that no valid input
		// can exceed and a nest of headers exhausts immediately. Once
		// it is spent nothing is allocated ahead of the elements, and
		// append and map assignment still grow to fit those that do
		// arrive.
		if d.budget < 0 {
			d.budget = max(avail, minInitLen)
		}
		if n > d.budget {
			n = d.budget
		}
		d.budget -= n
	}

	return n
}

// minInitLen is the smallest collection we will size from the input remaining,
// below which the clip costs more in reallocation than it saves.
const minInitLen = 64

// maxDepth is how deeply the input may nest values before decoding gives up.
//
// Every level of nesting is a level of recursion, and a container header can
// be a single byte, so a body of nothing but headers costs a stack frame per
// byte. At around 512 bytes a frame, 2mb of them exhausts the 1gb a goroutine
// stack may grow to, which is a fatal error that cannot be recovered.
//
// encoding/json stops at the same depth, so input too deeply nested for one
// format is too deeply nested for the other.
const maxDepth = 10000

var errNestingTooDeep = fmt.Errorf("msgpack: input nests more than %d levels deep", maxDepth)

// enter records the start of a nested value. If it returns an error the value
// is too deeply nested to decode and nothing has been recorded, so the caller
// returns without calling leave; otherwise the caller must call leave once it
// has finished with the value.
func (d *Decoder) enter() error {
	d.depth++
	if d.depth > maxDepth {
		d.depth--
		return errNestingTooDeep
	}
	return nil
}

func (d *Decoder) leave() {
	d.depth--
}

// bytesAvailable reports a lower bound on the input still to be read, or -1 if
// the reader cannot report it at all.
func (d *Decoder) bytesAvailable() int {
	if d.lenr != nil {
		return d.lenr.Len()
	}
	if d.bufr != nil {
		return d.bufr.Buffered()
	}
	return -1
}

// readNInto reads n bytes into b, which it grows or replaces as needed.
//
// n comes from a str, bin or ext header, so it is declared by the stream and
// not yet backed by any data: a five-byte bin32 header can declare 4gb. Unless
// alloc limits are disabled it therefore grows in bytesAllocLimit steps as the
// data arrives, rather than allocating the declared length up front, so a
// header longer than the data that follows costs one step and an error.
//
// This is the counterpart of Decoder.readN, which makes the same choice for
// the decoder's own scratch buffer, and exists because the value read here is
// returned to the caller and so cannot share that buffer.
func (d *Decoder) readNInto(b []byte, n int) ([]byte, error) {
	if d.flags&disableAllocLimitFlag != 0 {
		return readN(d.r, b, n)
	}
	return readNGrow(d.r, b, n)
}

func readN(r io.Reader, b []byte, n int) ([]byte, error) {
	if b == nil {
		if n == 0 {
			return make([]byte, 0), nil
		}
		b = make([]byte, 0, n)
	}

	if n > cap(b) {
		b = append(b, make([]byte, n-len(b))...)
	} else if n <= cap(b) {
		b = b[:n]
	}

	_, err := io.ReadFull(r, b)
	return b, err
}

func readNGrow(r io.Reader, b []byte, n int) ([]byte, error) {
	if b == nil {
		if n == 0 {
			return make([]byte, 0), nil
		}
		switch {
		case n < 64:
			b = make([]byte, 0, 64)
		case n <= bytesAllocLimit:
			b = make([]byte, 0, n)
		default:
			b = make([]byte, 0, bytesAllocLimit)
		}
	}

	if n <= cap(b) {
		b = b[:n]
		_, err := io.ReadFull(r, b)
		return b, err
	}
	b = b[:cap(b)]

	var pos int
	for {
		alloc := min(n-len(b), bytesAllocLimit)
		b = append(b, make([]byte, alloc)...)

		_, err := io.ReadFull(r, b[pos:])
		if err != nil {
			return b, err
		}

		if len(b) == n {
			break
		}
		pos = len(b)
	}

	return b, nil
}

func min(a, b int) int { //nolint:unparam
	if a <= b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
