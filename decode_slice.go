package msgpack

import (
	"fmt"
	"reflect"

	"github.com/vmihailenco/msgpack/v5/msgpcode"
)

var sliceStringPtrType = reflect.TypeOf((*[]string)(nil))

// DecodeArrayLen decodes array length. Length is -1 when array is nil.
func (d *Decoder) DecodeArrayLen() (int, error) {
	c, err := d.readCode()
	if err != nil {
		return 0, err
	}
	return d.arrayLen(c)
}

func (d *Decoder) arrayLen(c byte) (int, error) {
	if c == msgpcode.Nil {
		return -1, nil
	} else if c >= msgpcode.FixedArrayLow && c <= msgpcode.FixedArrayHigh {
		return int(c & msgpcode.FixedArrayMask), nil
	}
	switch c {
	case msgpcode.Array16:
		n, err := d.uint16()
		return int(n), err
	case msgpcode.Array32:
		n, err := d.uint32()
		return int(n), err
	}
	return 0, fmt.Errorf("msgpack: invalid code=%x decoding array length", c)
}

func decodeStringSliceValue(d *Decoder, v reflect.Value) error {
	ptr := v.Addr().Convert(sliceStringPtrType).Interface().(*[]string)
	return d.decodeStringSlicePtr(ptr)
}

func (d *Decoder) decodeStringSlicePtr(ptr *[]string) error {
	n, err := d.DecodeArrayLen()
	if err != nil {
		return err
	}
	if n == -1 {
		return nil
	}

	ss := makeStrings(*ptr, d.initLen(n, sliceAllocLimit, minBytesPerArrayElem))
	for i := 0; i < n; i++ {
		s, err := d.DecodeString()
		if err != nil {
			return err
		}
		ss = append(ss, s)
	}
	*ptr = ss

	return nil
}

// minBytesPerArrayElem is the least an array element can cost to encode: a
// one-byte fixint, nil or bool.
const minBytesPerArrayElem = 1

func makeStrings(s []string, n int) []string {
	if s == nil {
		return make([]string, 0, n)
	}

	if cap(s) >= n {
		return s[:0]
	}

	s = s[:cap(s)]
	s = append(s, make([]string, n-len(s))...)
	return s[:0]
}

func decodeSliceValue(d *Decoder, v reflect.Value) error {
	n, err := d.DecodeArrayLen()
	if err != nil {
		return err
	}

	if n == -1 {
		v.Set(reflect.Zero(v.Type()))
		return nil
	}
	if n == 0 && v.IsNil() {
		v.Set(reflect.MakeSlice(v.Type(), 0, 0))
		return nil
	}

	if v.Cap() >= n {
		v.Set(v.Slice(0, n))
	} else if v.Len() < v.Cap() {
		v.Set(v.Slice(0, v.Cap()))
	}

	noLimit := d.flags&disableAllocLimitFlag != 0

	if noLimit && n > v.Len() {
		v.Set(growSliceValue(v, n, d.initLen(n, sliceAllocLimit, minBytesPerArrayElem)))
	}

	for i := 0; i < n; i++ {
		if !noLimit && i >= v.Len() {
			v.Set(growSliceValue(v, n, d.initLen(n, sliceAllocLimit, minBytesPerArrayElem)))
		}

		elem := v.Index(i)
		if err := d.DecodeValue(elem); err != nil {
			return err
		}
	}

	return nil
}

// growSliceValue grows v towards n elements, by at most maxStep at a time, so
// that a declared n far larger than the data behind it is never allocated in
// one go. The caller loops until v is long enough for the elements that
// actually arrive, and indexes what it grew, so v must always gain at least
// one element however small a step it was given. The floor is minInitLen
// rather than one element to avoid a reallocation per element; growing past
// the elements n declares is still ruled out.
func growSliceValue(v reflect.Value, n, maxStep int) reflect.Value {
	diff := min(max(maxStep, minInitLen), n-v.Len())
	return reflect.AppendSlice(v, reflect.MakeSlice(v.Type(), diff, diff))
}

func decodeArrayValue(d *Decoder, v reflect.Value) error {
	n, err := d.DecodeArrayLen()
	if err != nil {
		return err
	}

	if n == -1 {
		return nil
	}
	if n > v.Len() {
		return fmt.Errorf("%s len is %d, but msgpack has %d elements", v.Type(), v.Len(), n)
	}

	for i := 0; i < n; i++ {
		sv := v.Index(i)
		if err := d.DecodeValue(sv); err != nil {
			return err
		}
	}

	return nil
}

func (d *Decoder) DecodeSlice() ([]interface{}, error) {
	c, err := d.readCode()
	if err != nil {
		return nil, err
	}
	return d.decodeSlice(c)
}

func (d *Decoder) decodeSlice(c byte) ([]interface{}, error) {
	n, err := d.arrayLen(c)
	if err != nil {
		return nil, err
	}
	if n == -1 {
		return nil, nil
	}

	// Never pre-allocate based on the untrusted, declared element count.
	// append still grows to fit the data actually present.
	s := make([]interface{}, 0, d.initLen(n, sliceAllocLimit, minBytesPerArrayElem))
	for i := 0; i < n; i++ {
		v, err := d.decodeInterfaceCond()
		if err != nil {
			return nil, err
		}
		s = append(s, v)
	}

	return s, nil
}

func (d *Decoder) skipSlice(c byte) error {
	n, err := d.arrayLen(c)
	if err != nil {
		return err
	}

	for i := 0; i < n; i++ {
		if err := d.Skip(); err != nil {
			return err
		}
	}

	return nil
}
