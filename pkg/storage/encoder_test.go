package storage

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valkey-io/valkey-go"
	"github.com/valyala/bytebufferpool"
)

func TestGobEncoder(t *testing.T) {
	type testStruct struct {
		B []byte
		S string
		I int
	}
	tstruct := testStruct{
		B: []byte("rand"),
		S: "test",
		I: 1,
	}

	encoder := GobEncoder{}
	encoded, err := encoder.Encode(tstruct)
	assert.NoError(t, err)
	assert.NotEmpty(t, encoded)

	// Encode a different struct to ensure pooled buffer reuse does not overwrite encoded
	_, err = encoder.Encode(testStruct{B: []byte("other-payload"), S: "other", I: 99})
	assert.NoError(t, err)

	decoded := testStruct{}
	assert.NoError(t, encoder.Decode(encoded, &decoded))
	assert.Equal(t, tstruct, decoded)
	assert.Equal(t, tstruct.B, decoded.B)
}

func TestGobEncoderStream(t *testing.T) {
	type testStruct struct {
		B []byte
		S string
		I int
	}
	tstruct := testStruct{
		B: []byte("rand"),
		S: "test",
		I: 1,
	}

	encoder := GobEncoder{}
	buf := bytebufferpool.Get()
	defer bytebufferpool.Put(buf)

	err := encoder.EncodeStream(buf, tstruct)
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.Bytes())

	decoded := testStruct{}
	assert.NoError(t, encoder.DecodeStream(bytes.NewReader(buf.Bytes()), &decoded))
	assert.Equal(t, tstruct, decoded)
}

func TestAESEncryptor_DecryptWriter_ChunkBoundaries(t *testing.T) {
	t.Parallel()
	key := GenerateRandomKey(32)
	enc, err := NewDefaultEncryptor(key)
	require.NoError(t, err)

	payloadSizes := []int{0, 1, 15, 16, 17, 32768, 32769, 100000}
	chunkSizes := []int{1, 15, 16, 17, 32769}

	for _, pSize := range payloadSizes {
		plaintext := make([]byte, pSize)
		for i := range plaintext {
			plaintext[i] = byte((i*31 + 7) & 0xff)
		}

		ciphertext, cerr := enc.EncryptBytes(plaintext)
		require.NoError(t, cerr)
		require.Len(t, ciphertext, 16+pSize)

		for _, cSize := range chunkSizes {
			var out bytes.Buffer
			out.Grow(pSize)
			dw := enc.NewDecryptWriter(&out)

			for offset := 0; offset < len(ciphertext); offset += cSize {
				end := min(offset+cSize, len(ciphertext))
				n, wErr := dw.Write(ciphertext[offset:end])
				require.NoError(t, wErr)
				require.Equal(t, end-offset, n)
			}

			require.NoError(t, dw.Close())
			if pSize == 0 {
				assert.Empty(t, out.Bytes(), "payloadSize=%d chunkSize=%d", pSize, cSize)
			} else {
				assert.Equal(t, plaintext, out.Bytes(), "payloadSize=%d chunkSize=%d", pSize, cSize)
			}
		}
	}

	// Verify truncated IV (< 16 bytes) returns io.ErrUnexpectedEOF on Close()
	for _, shortLen := range []int{0, 1, 15} {
		dw := enc.NewDecryptWriter(io.Discard)
		if shortLen > 0 {
			_, cerr := dw.Write(make([]byte, shortLen))
			require.NoError(t, cerr)
		}
		require.ErrorIs(t, dw.Close(), io.ErrUnexpectedEOF)
	}

	// Verify zero heap allocations per Write after IV initialization
	dw := enc.NewDecryptWriter(io.Discard)
	_, err = dw.Write(make([]byte, 16))
	require.NoError(t, err)
	sampleChunk := make([]byte, 4096)
	allocs := testing.AllocsPerRun(100, func() {
		_, _ = dw.Write(sampleChunk)
	})
	assert.InEpsilon(t, float64(0), allocs, 0)
}

func TestAESEncryptor_ChunkedEncryptStream(t *testing.T) {
	t.Parallel()
	key := GenerateRandomKey(32)
	enc, err := NewDefaultEncryptor(key)
	require.NoError(t, err)

	plaintext := make([]byte, 100000)
	for i := range plaintext {
		plaintext[i] = byte((i*17 + 3) & 0xff)
	}

	var cipherBuf bytes.Buffer
	ew, err := enc.EncryptStream(&cipherBuf)
	require.NoError(t, err)

	n, err := ew.Write(plaintext)
	require.NoError(t, err)
	require.Equal(t, len(plaintext), n)

	dr, err := enc.DecryptStream(&cipherBuf)
	require.NoError(t, err)

	decrypted, err := io.ReadAll(dr)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestStorageRecord_MetadataOnlyGob(t *testing.T) {
	t.Parallel()
	encoder := GobEncoder{}
	pass := "secret-pass"
	exp := time.Now().UTC().Truncate(time.Millisecond)
	sr := storageRecord{
		ID:         "sec-123",
		Value:      "confidential message",
		Passphrase: &pass,
		ExpiresAt:  exp,
		Files: []storageFileMeta{
			{Name: "installer.msi", Size: 54673408},
			{Name: "empty.txt", Size: 0},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, encoder.EncodeStream(&buf, sr))
	// Metadata record must remain tiny (< 512 bytes) even for a 52 MB file
	assert.Less(t, buf.Len(), 512)

	var decoded storageRecord
	require.NoError(t, encoder.DecodeStream(&buf, &decoded))
	assert.Equal(t, sr, decoded)

	files := make([]*FileRecord, len(decoded.Files))
	for i, fm := range decoded.Files {
		files[i] = &FileRecord{
			Name:    fm.Name,
			Size:    fm.Size,
			Content: nil,
		}
	}
	assert.Equal(t, "installer.msi", files[0].Name)
	assert.Equal(t, int64(54673408), files[0].Size)
	assert.Nil(t, files[0].Content)
}

type testRecord struct {
	id         ID
	key        Key
	expiration time.Duration
	maxViews   uint64
	passphrase *string
	value      string
	expiresAt  time.Time
	files      []*FileRecord
}

func (r *testRecord) ID() ID                    { return r.id }
func (r *testRecord) Key() Key                  { return r.key }
func (r *testRecord) Expiration() time.Duration { return r.expiration }
func (r *testRecord) ExpiresAt() time.Time      { return r.expiresAt }
func (r *testRecord) MaxViews() uint64          { return r.maxViews }
func (r *testRecord) Passphrase() *string       { return r.passphrase }
func (r *testRecord) Value() string             { return r.value }
func (r *testRecord) SetValue(v string)         { r.value = v }
func (r *testRecord) SetPassphrase(p string)    { r.passphrase = &p }
func (r *testRecord) Files() []*FileRecord      { return r.files }
func (r *testRecord) Seal()                     { r.expiresAt = time.Now().Add(r.expiration).UTC() }

func (r *testRecord) Reinit(v string, p *string, exp time.Time, f []*FileRecord) {
	r.value = v
	r.passphrase = p
	r.expiresAt = exp
	r.files = f
}

type miniRESPServer struct {
	mu     sync.Mutex
	kv     map[string]string
	hashes map[string]map[string]string
}

func startMiniRESPServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	srv := &miniRESPServer{
		mu:     sync.Mutex{},
		kv:     make(map[string]string),
		hashes: make(map[string]map[string]string),
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handleConn(conn)
		}
	}()
	return ln.Addr().String()
}

func (s *miniRESPServer) handleConn(conn net.Conn) { //nolint:gocognit,cyclop // it's test
	defer conn.Close()
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) == 0 || line[0] != '*' {
			return
		}
		argc, err := strconv.Atoi(line[1:])
		if err != nil {
			return
		}
		args := make([]string, argc)
		for i := range argc {
			lenLine, err := r.ReadString('\n')
			if err != nil {
				return
			}
			lenLine = strings.TrimRight(lenLine, "\r\n")
			n, err := strconv.Atoi(lenLine[1:])
			if err != nil {
				return
			}
			buf := make([]byte, n+2)
			if _, err := io.ReadFull(r, buf); err != nil {
				return
			}
			args[i] = string(buf[:n])
		}

		s.mu.Lock()
		cmd := strings.ToUpper(args[0])
		switch cmd {
		case "SET":
			key, val := args[1], args[2]
			nx := false
			for _, a := range args[3:] {
				if strings.EqualFold(a, "NX") {
					nx = true
				}
			}
			if nx {
				if _, exists := s.kv[key]; exists {
					_, _ = w.WriteString("$-1\r\n")
					break
				}
			}
			s.kv[key] = val
			_, _ = w.WriteString("+OK\r\n")
		case "GET":
			val, ok := s.kv[args[1]]
			if !ok {
				_, _ = w.WriteString("$-1\r\n")
			} else {
				_, _ = fmt.Fprintf(w, "$%d\r\n%s\r\n", len(val), val)
			}
		case "EXISTS":
			if _, ok := s.kv[args[1]]; ok {
				_, _ = w.WriteString(":1\r\n")
			} else if _, ok := s.hashes[args[1]]; ok {
				_, _ = w.WriteString(":1\r\n")
			} else {
				_, _ = w.WriteString(":0\r\n")
			}
		case "DEL":
			deleted := 0
			for _, k := range args[1:] {
				if _, ok := s.kv[k]; ok {
					delete(s.kv, k)
					deleted++
				}
				if _, ok := s.hashes[k]; ok {
					delete(s.hashes, k)
					deleted++
				}
			}
			_, _ = fmt.Fprintf(w, ":%d\r\n", deleted)
		case "HSET":
			key := args[1]
			if s.hashes[key] == nil {
				s.hashes[key] = make(map[string]string)
			}
			added := 0
			for i := 2; i+1 < len(args); i += 2 {
				s.hashes[key][args[i]] = args[i+1]
				added++
			}
			_, _ = fmt.Fprintf(w, ":%d\r\n", added)
		case "HEXISTS":
			h := s.hashes[args[1]]
			if h != nil {
				if _, ok := h[args[2]]; ok {
					_, _ = w.WriteString(":1\r\n")
					break
				}
			}
			_, _ = w.WriteString(":0\r\n")
		case "HGET":
			h := s.hashes[args[1]]
			if h == nil {
				_, _ = w.WriteString("$-1\r\n")
				break
			}
			val, ok := h[args[2]]
			if !ok {
				_, _ = w.WriteString("$-1\r\n")
			} else {
				_, _ = fmt.Fprintf(w, "$%d\r\n%s\r\n", len(val), val)
			}
		case "EXPIRE":
			_, _ = w.WriteString(":1\r\n")
		default:
			_, _ = w.WriteString("+OK\r\n")
		}
		s.mu.Unlock()
		_ = w.Flush()
	}
}

func TestValkeyStorage_StoreLoadAndStreamFile(t *testing.T) {
	t.Parallel()
	addr := startMiniRESPServer(t)
	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress:       []string{addr},
		AlwaysRESP2:       true,
		DisableCache:      true,
		ClientSetInfo:     []string{},
		ForceSingleClient: true,
	})
	require.NoError(t, err)
	defer client.Close()

	store := NewValkey(client, nil, func(id ID, k Key) Record[ID, Key] {
		return &testRecord{
			id:         id,
			key:        k,
			expiration: 0,
			maxViews:   0,
			passphrase: nil,
			value:      "",
			expiresAt:  time.Time{},
			files:      nil,
		}
	})

	ctx := context.Background()
	key := Key(GenerateRandomKey(32))
	file0Bytes := bytes.Repeat([]byte("attachment-zero-payload-"), 2000) // ~48 KB (> 32 KB chunk size)
	file2Bytes := []byte("attachment-two-small")

	rec := &testRecord{
		id:         "sec-stream-1",
		key:        key,
		expiration: 10 * time.Minute,
		maxViews:   2,
		passphrase: nil,
		value:      "top-secret-text",
		expiresAt:  time.Time{},
		files: []*FileRecord{
			{Name: "first.bin", Size: int64(len(file0Bytes)), Content: bytes.Clone(file0Bytes)},
			{Name: "empty.txt", Size: 0, Content: []byte{}},
			{Name: "third.bin", Size: int64(len(file2Bytes)), Content: bytes.Clone(file2Bytes)},
		},
	}

	_, err = store.Store(ctx, rec)
	require.NoError(t, err)

	// Load must reconstruct file names & sizes with nil Content
	loaded, err := store.Load(ctx, "sec-stream-1", key)
	require.NoError(t, err)
	require.Equal(t, "top-secret-text", loaded.Value())
	require.Len(t, loaded.Files(), 3)

	assert.Equal(t, "first.bin", loaded.Files()[0].Name)
	assert.Equal(t, int64(len(file0Bytes)), loaded.Files()[0].Size)
	assert.Nil(t, loaded.Files()[0].Content)

	assert.Equal(t, "empty.txt", loaded.Files()[1].Name)
	assert.Equal(t, int64(0), loaded.Files()[1].Size)
	assert.Nil(t, loaded.Files()[1].Content)

	assert.Equal(t, "third.bin", loaded.Files()[2].Name)
	assert.Equal(t, int64(len(file2Bytes)), loaded.Files()[2].Size)
	assert.Nil(t, loaded.Files()[2].Content)

	// StreamFile must stream back the exact original bytes for non-empty files
	var out0 bytes.Buffer
	require.NoError(t, store.StreamFile(ctx, "sec-stream-1", key, 0, &out0))
	assert.Equal(t, file0Bytes, out0.Bytes())

	// Index 1 was an empty file (skipped in HSET), so index 2 still maps to "2"
	var out2 bytes.Buffer
	require.NoError(t, store.StreamFile(ctx, "sec-stream-1", key, 2, &out2))
	assert.Equal(t, file2Bytes, out2.Bytes())

	// Missing index returns ErrRecordNotFound without writing anything
	var outMissing bytes.Buffer
	require.ErrorIs(t, store.StreamFile(ctx, "sec-stream-1", key, 99, &outMissing), ErrRecordNotFound)
	assert.Empty(t, outMissing.Bytes())

	// Burn deletes both the metadata and the files hash
	require.NoError(t, store.Burn(ctx, "sec-stream-1"))
	assert.ErrorIs(t, store.StreamFile(ctx, "sec-stream-1", key, 0, &outMissing), ErrRecordNotFound)
}
