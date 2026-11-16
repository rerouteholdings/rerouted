// Package wire holds Tieroute v1 wire types and encoding (SPEC §4): I-JSON bodies,
// byte strings as unpadded base64url, and JCS (RFC 8785) for everything signed or hashed.
package wire

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode/utf16"
	"unicode/utf8"
)

// MediaType is the content type of every JSON body (spec/api/conventions.md).
const MediaType = "application/tieroute+json"

// SigContext is the first element of every signature input (SPEC §4.3).
const SigContext = "tieroute/v1"

// Raw is a JSON value carried through without decoding.
type Raw = json.RawMessage

// maxSafe is the largest integer I-JSON allows (RFC 7493 §2.2).
const maxSafe = 1<<53 - 1

var b64 = base64.RawURLEncoding.Strict()

// Bytes is a byte string, carried in JSON as unpadded base64url (SPEC §4.1).
// Its underlying type is []byte, so it converts to and from []byte freely.
type Bytes []byte

func (b Bytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(b64.EncodeToString(b))
}

func (b *Bytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("wire: expected a base64url string: %w", err)
	}
	d, err := DecodeB64(s)
	if err != nil {
		return err
	}
	*b = d
	return nil
}

// B64 encodes b as unpadded base64url.
func B64(b []byte) string { return b64.EncodeToString(b) }

// DecodeB64 decodes unpadded base64url, rejecting padding and non-canonical encodings.
func DecodeB64(s string) ([]byte, error) {
	if strings.ContainsAny(s, "=+/") {
		return nil, errors.New("wire: not unpadded base64url")
	}
	d, err := b64.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("wire: bad base64url: %w", err)
	}
	return d, nil
}

// Marshal encodes v as JCS (RFC 8785). []byte values become base64url strings,
// struct fields follow their json tags, and json.RawMessage is re-canonicalized.
// Every number must be an integer within ±(2^53 − 1).
func Marshal(v any) ([]byte, error) {
	t, err := normalize(reflect.ValueOf(v))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeJCS(&buf, t); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Unmarshal decodes an I-JSON body into v. Any formatting is accepted, but duplicate
// member names, invalid UTF-8, non-integer numbers, and trailing data are rejected, and so
// is a member named like one of v's in another case: names are matched exactly.
func Unmarshal(data []byte, v any) error {
	if err := checkIJSON(data, reflect.TypeOf(v)); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	return d.Decode(v)
}

// UnmarshalClosed is Unmarshal for closed schemas (SPEC §20.2): members that v's
// struct doesn't declare are rejected instead of ignored.
func UnmarshalClosed(data []byte, v any) error {
	if err := checkIJSON(data, reflect.TypeOf(v)); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	d.DisallowUnknownFields()
	return d.Decode(v)
}

// Canonical re-encodes any I-JSON value as JCS.
func Canonical(data []byte) ([]byte, error) {
	if err := CheckIJSON(data); err != nil {
		return nil, err
	}
	var v any
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	return Marshal(v)
}

var (
	ErrDuplicateName = errors.New("wire: duplicate member name")
	ErrNotInteger    = errors.New("wire: numbers must be integers within ±(2^53 − 1)")
	ErrSurrogate     = errors.New("wire: a lone surrogate isn't I-JSON")
	ErrMemberCase    = errors.New("wire: member name in the wrong case")
	ErrTooDeep       = errors.New("wire: nested too deeply")
)

// MaxDepth is how deeply a value's arrays and objects may nest. Nothing in the protocol
// comes near it, and each level costs memory to check.
const MaxDepth = 128

// CheckIJSON verifies data is exactly one I-JSON value (RFC 7493) with integer numbers,
// nested no deeper than MaxDepth.
func CheckIJSON(data []byte) error { return checkIJSON(data, nil) }

// checkIJSON is CheckIJSON for a value about to be decoded into a Go value of type root
// (nil for any). It also refuses a member whose name matches one of a struct's fields in
// everything but case (ErrMemberCase): encoding/json would take "ID" for "id", so an object
// a stricter reader refuses, or reads differently, would be accepted here.
func checkIJSON(data []byte, root reflect.Type) error {
	if !utf8.Valid(data) {
		return errors.New("wire: invalid UTF-8")
	}
	if err := checkSurrogates(data); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	type frame struct {
		obj    bool
		names  map[string]bool
		key    bool         // in an object: the next token is a member name (or '}')
		fields *fieldSet    // the struct this object decodes into, if it's one
		elem   reflect.Type // what this array's elements, or this map's values, decode into
	}
	var stack []*frame
	values := 0
	next := root // the Go type the next value decodes into; nil if unknown
	// valueDone marks the end of a value: in an object, a member name comes next.
	valueDone := func() {
		if len(stack) == 0 {
			values++
		} else if top := stack[len(stack)-1]; top.obj {
			top.key = true
		}
	}
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("wire: %w", err)
		}
		if delim, ok := tok.(json.Delim); ok && (delim == '}' || delim == ']') {
			stack = stack[:len(stack)-1]
			valueDone()
			continue
		}
		if n := len(stack); n > 0 && stack[n-1].obj && stack[n-1].key {
			top := stack[n-1]
			name := tok.(string)
			if top.names[name] {
				return fmt.Errorf("%w: %q", ErrDuplicateName, name)
			}
			top.names[name] = true
			top.key = false
			next = top.elem
			if top.fields != nil {
				t, ok := top.fields.exact[name]
				if !ok && top.fields.folds(name) {
					return fmt.Errorf("%w: %q", ErrMemberCase, name)
				}
				next = t
			}
			continue
		}
		if n := len(stack); n > 0 && !stack[n-1].obj {
			next = stack[n-1].elem
		}
		switch t := tok.(type) {
		case json.Delim: // '{' or '['
			if len(stack) >= MaxDepth {
				return ErrTooDeep
			}
			f := &frame{obj: t == '{', key: t == '{'}
			into := container(next)
			if f.obj {
				f.names = map[string]bool{}
				if into != nil && into.Kind() == reflect.Struct {
					f.fields = fieldsOf(into)
				} else if into != nil && into.Kind() == reflect.Map {
					f.elem = into.Elem()
				}
			} else if into != nil && (into.Kind() == reflect.Slice || into.Kind() == reflect.Array) {
				f.elem = into.Elem()
			}
			stack = append(stack, f)
			continue
		case json.Number:
			if _, err := parseInt(t); err != nil {
				return err
			}
		}
		valueDone()
	}
	if values != 1 {
		return errors.New("wire: expected exactly one JSON value")
	}
	return nil
}

var unmarshalerType = reflect.TypeFor[json.Unmarshaler]()

// container is the struct, map, slice, or array type a JSON object or array decodes into
// for a Go value of type t, or nil if that's unknown: an interface, or a type that decodes
// itself (wire.Raw, which is checked when it's decoded in turn).
func container(t reflect.Type) reflect.Type {
	for t != nil {
		if t.Implements(unmarshalerType) || reflect.PointerTo(t).Implements(unmarshalerType) {
			return nil
		}
		if t.Kind() != reflect.Pointer {
			break
		}
		t = t.Elem()
	}
	if t == nil || t.Kind() == reflect.Interface {
		return nil
	}
	return t
}

// fieldSet is a struct's JSON member names, as encoding/json sees them.
type fieldSet struct {
	exact map[string]reflect.Type
	names []string
}

// folds reports whether name matches a field's name in everything but case.
func (f *fieldSet) folds(name string) bool {
	for _, n := range f.names {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}

var fieldSets sync.Map // reflect.Type -> *fieldSet

func fieldsOf(t reflect.Type) *fieldSet {
	if f, ok := fieldSets.Load(t); ok {
		return f.(*fieldSet)
	}
	fs := &fieldSet{exact: map[string]reflect.Type{}}
	var add func(t reflect.Type, depth int)
	add = func(t reflect.Type, depth int) {
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if tag == "-" {
				continue
			}
			if f.Anonymous && tag == "" {
				// An embedded struct's fields are the outer one's, unless it names one itself.
				if et := container(f.Type); et != nil && et.Kind() == reflect.Struct && depth < 8 {
					add(et, depth+1)
					continue
				}
			}
			if !f.IsExported() {
				continue
			}
			name := tag
			if name == "" {
				name = f.Name
			}
			if _, dup := fs.exact[name]; !dup {
				fs.exact[name] = f.Type
				fs.names = append(fs.names, name)
			}
		}
	}
	add(t, 0)
	fieldSets.Store(t, fs)
	return fs
}

// checkSurrogates refuses a \u escape of a surrogate that isn't half of a pair: I-JSON has
// none (RFC 7493 §2.1), and encoding/json would turn it into U+FFFD, so another reader of
// the same bytes would see a different string. Raw UTF-8 can't encode one: utf8.Valid
// refuses it.
func checkSurrogates(data []byte) error {
	hex4 := func(i int) (rune, bool) {
		if i+6 > len(data) || data[i] != '\\' || data[i+1] != 'u' {
			return 0, false
		}
		r, err := strconv.ParseUint(string(data[i+2:i+6]), 16, 16)
		return rune(r), err == nil
	}
	in := false
	for i := 0; i < len(data); i++ {
		switch c := data[i]; {
		case c == '"':
			in = !in
		case in && c == '\\':
			r, ok := hex4(i)
			if !ok {
				i++ // \" or another one-character escape
				continue
			}
			switch {
			case r >= 0xD800 && r <= 0xDBFF:
				if lo, ok := hex4(i + 6); !ok || lo < 0xDC00 || lo > 0xDFFF {
					return ErrSurrogate
				}
				i += 11
			case r >= 0xDC00 && r <= 0xDFFF:
				return ErrSurrogate
			default:
				i += 5
			}
		}
	}
	return nil
}

func parseInt(n json.Number) (int64, error) {
	i, err := strconv.ParseInt(string(n), 10, 64)
	if err != nil || i > maxSafe || i < -maxSafe {
		return 0, ErrNotInteger
	}
	return i, nil
}

// ---- normalizing Go values to a JSON tree ----

var (
	rawType     = reflect.TypeFor[json.RawMessage]()
	numberType  = reflect.TypeFor[json.Number]()
	bytesType   = reflect.TypeFor[Bytes]()
	marshalType = reflect.TypeFor[json.Marshaler]()
)

// normalize turns v into nil, bool, string, int64, []any, or map[string]any.
func normalize(v reflect.Value) (any, error) {
	if !v.IsValid() {
		return nil, nil
	}
	t := v.Type()
	switch {
	case t == rawType:
		if v.IsNil() {
			return nil, nil
		}
		var x any
		d := json.NewDecoder(bytes.NewReader(v.Bytes()))
		d.UseNumber()
		if err := CheckIJSON(v.Bytes()); err != nil {
			return nil, err
		}
		if err := d.Decode(&x); err != nil {
			return nil, err
		}
		return normalize(reflect.ValueOf(x))
	case t == numberType:
		i, err := parseInt(json.Number(v.String()))
		if err != nil {
			return nil, err
		}
		return i, nil
	case t == bytesType || (t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Uint8):
		if v.IsNil() {
			return nil, nil
		}
		return b64.EncodeToString(v.Bytes()), nil
	}
	switch t.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return nil, nil
		}
		return normalize(v.Elem())
	}
	if t.Implements(marshalType) {
		b, err := v.Interface().(json.Marshaler).MarshalJSON()
		if err != nil {
			return nil, err
		}
		return normalize(reflect.ValueOf(json.RawMessage(b)))
	}
	switch t.Kind() {
	case reflect.Bool:
		return v.Bool(), nil
	case reflect.String:
		return v.String(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		i := v.Int()
		if i > maxSafe || i < -maxSafe {
			return nil, ErrNotInteger
		}
		return i, nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		u := v.Uint()
		if u > maxSafe {
			return nil, ErrNotInteger
		}
		return int64(u), nil
	case reflect.Float32, reflect.Float64:
		f := v.Float()
		if f != math.Trunc(f) || math.Abs(f) > maxSafe {
			return nil, ErrNotInteger
		}
		return int64(f), nil
	case reflect.Slice, reflect.Array:
		if t.Kind() == reflect.Slice && v.IsNil() {
			return nil, nil
		}
		out := make([]any, v.Len())
		for i := range out {
			x, err := normalize(v.Index(i))
			if err != nil {
				return nil, err
			}
			out[i] = x
		}
		return out, nil
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			return nil, fmt.Errorf("wire: map keys must be strings, not %s", t.Key())
		}
		if v.IsNil() {
			return nil, nil
		}
		out := make(map[string]any, v.Len())
		it := v.MapRange()
		for it.Next() {
			x, err := normalize(it.Value())
			if err != nil {
				return nil, err
			}
			out[it.Key().String()] = x
		}
		return out, nil
	case reflect.Struct:
		out := map[string]any{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			fv := v.Field(i)
			if strings.Contains(opts, "omitempty") && isEmpty(fv) {
				continue
			}
			x, err := normalize(fv)
			if err != nil {
				return nil, err
			}
			out[name] = x
		}
		return out, nil
	}
	return nil, fmt.Errorf("wire: can't encode %s", t)
}

func isEmpty(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Slice, reflect.Map, reflect.String, reflect.Array:
		return v.Len() == 0
	case reflect.Pointer, reflect.Interface:
		return v.IsNil()
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint() == 0
	}
	return false
}

// ---- JCS (RFC 8785) for the value types Tieroute uses ----

func writeJCS(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		buf.WriteString(strconv.FormatBool(x))
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
	case string:
		return writeString(buf, x)
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeJCS(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		names := make([]string, 0, len(x))
		for k := range x {
			names = append(names, k)
		}
		// Member names sort by UTF-16 code units (RFC 8785 §3.2.3).
		slices.SortFunc(names, func(a, b string) int { return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b))) })
		buf.WriteByte('{')
		for i, k := range names {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeJCS(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("wire: can't canonicalize %T", v)
	}
	return nil
}

// writeString escapes like ECMAScript JSON.stringify, as JCS requires.
func writeString(buf *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return errors.New("wire: invalid UTF-8 in a string")
	}
	const hex = "0123456789abcdef"
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hex[r>>4])
				buf.WriteByte(hex[r&15])
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
	return nil
}
