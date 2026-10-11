// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
// SPDX-License-Identifier: EUPL-1.2

package decision

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"github.com/tetratelabs/wazero/api"
)

// Bounds of the interface, equal to the engine's.
const (
	// DigestBytes is the width of a record digest (SHA-256).
	DigestBytes = 32
	// MaxSignatureBytes is the longest signature a Signer may return.
	MaxSignatureBytes = 512
	// MaxKeyIDBytes is the longest key identifier.
	MaxKeyIDBytes = 64
)

// Clock is the host's wall clock.
type Clock interface {
	// Now returns whole seconds since the Unix epoch. An error, or a time
	// before the epoch, blocks the decision and halts the engine.
	Now(ctx context.Context) (int64, error)
}

// Signer signs record digests under the key the Config names.
type Signer interface {
	// Sign returns the signature over digest, 1 to MaxSignatureBytes bytes.
	// An error, or a signature outside that range, blocks the decision and
	// halts the engine; nothing unsigned is offered to the Sink.
	Sign(ctx context.Context, digest [DigestBytes]byte) ([]byte, error)
}

// Sink stores audit records.
type Sink interface {
	// Append returns nil only once the record is durable; within is the time
	// the engine allows for it. An error blocks the decision and halts the
	// engine, and the engine keeps no record the Sink does not hold.
	Append(ctx context.Context, record Record, within time.Duration) error
}

// Record is one sealed audit record as the Sink receives it. The loader has
// checked that Digest is the SHA-256 of Preimage before the Sink sees it.
type Record struct {
	// Preimage is the canonical encoding the digest covers; it holds the
	// digest of the record before it, which makes the records a chain.
	Preimage []byte
	// Digest is the SHA-256 of Preimage.
	Digest [DigestBytes]byte
	// KeyID names the key the Signer signed with.
	KeyID string
	// Signature is the Signer's signature over Digest.
	Signature []byte
}

const (
	hostModule = "amussis_host_v1"
	// hostUnavailable is the answer of a clock or signer that cannot deliver.
	hostUnavailable = -1
	sinkStored      = 0
	sinkNotStored   = 1
	frameVersion    = 1
)

var errFrame = errors.New("the record frame is malformed")

// host holds the three effects and serves them to the module. Every path
// that cannot deliver an effect answers with the failure value; none of them
// puts a time, a signature or a stored record in its place.
type host struct {
	clock  Clock
	signer Signer
	sink   Sink
}

// hostFunction is one import of the module.
type hostFunction struct {
	name            string
	call            api.GoModuleFunc
	params, results []api.ValueType
}

func (h *host) functions() []hostFunction {
	i32, i64 := api.ValueTypeI32, api.ValueTypeI64
	return []hostFunction{
		{"clock_now", h.clockNow, nil, []api.ValueType{i64}},
		{"signer_sign", h.signerSign, []api.ValueType{i32, i32, i32}, []api.ValueType{i32}},
		{"sink_append", h.sinkAppend, []api.ValueType{i32, i32, i32}, []api.ValueType{i32}},
	}
}

func (h *host) clockNow(ctx context.Context, _ api.Module, stack []uint64) {
	now, err := h.clock.Now(ctx)
	if err != nil || now < 0 {
		now = hostUnavailable
	}
	stack[0] = api.EncodeI64(now)
}

func (h *host) signerSign(ctx context.Context, module api.Module, stack []uint64) {
	digestAt, outAt, capacity := api.DecodeU32(stack[0]), api.DecodeU32(stack[1]), api.DecodeU32(stack[2])
	stack[0] = api.EncodeI32(h.sign(ctx, module.Memory(), digestAt, outAt, capacity))
}

func (h *host) sign(ctx context.Context, memory api.Memory, digestAt, outAt, capacity uint32) int32 {
	view, ok := memory.Read(digestAt, DigestBytes)
	if !ok {
		return hostUnavailable
	}
	signature, err := h.signer.Sign(ctx, [DigestBytes]byte(view))
	length := len(signature)
	if err != nil || length == 0 || length > MaxSignatureBytes || uint64(length) > uint64(capacity) {
		return hostUnavailable
	}
	if !memory.Write(outAt, signature) {
		return hostUnavailable
	}
	return int32(length)
}

func (h *host) sinkAppend(ctx context.Context, module api.Module, stack []uint64) {
	frameAt, length, millis := api.DecodeU32(stack[0]), api.DecodeU32(stack[1]), api.DecodeU32(stack[2])
	stack[0] = api.EncodeI32(h.store(ctx, module.Memory(), frameAt, length, millis))
}

func (h *host) store(ctx context.Context, memory api.Memory, frameAt, length, millis uint32) int32 {
	view, ok := memory.Read(frameAt, length)
	if !ok || millis == 0 {
		return sinkNotStored
	}
	// The view is the module's memory; the Sink keeps its own copy.
	record, err := parseFrame(bytes.Clone(view))
	if err != nil {
		return sinkNotStored
	}
	if err := h.sink.Append(ctx, record, time.Duration(millis)*time.Millisecond); err != nil {
		return sinkNotStored
	}
	return sinkStored
}

// parseFrame splits one record frame: version, pre-image, digest, key
// identifier and signature, each length-prefixed, with nothing after them. It
// refuses a frame whose digest is not the SHA-256 of its pre-image.
func parseFrame(frame []byte) (Record, error) {
	if len(frame) == 0 || frame[0] != frameVersion {
		return Record{}, errFrame
	}
	rest := frame[1:]
	preimage, ok := take(&rest, 2)
	digest, okDigest := takeBytes(&rest, DigestBytes)
	keyID, okKey := take(&rest, 1)
	signature, okSignature := take(&rest, 2)
	if !ok || !okDigest || !okKey || !okSignature || len(rest) != 0 {
		return Record{}, errFrame
	}
	record := Record{Preimage: preimage, Digest: [DigestBytes]byte(digest), KeyID: string(keyID), Signature: signature}
	if sha256.Sum256(preimage) != record.Digest || len(keyID) == 0 || len(signature) == 0 {
		return Record{}, errFrame
	}
	return record, nil
}

// take reads a little-endian length of prefix bytes (1 or 2), then that many bytes.
func take(rest *[]byte, prefix int) ([]byte, bool) {
	head, ok := takeBytes(rest, prefix)
	if !ok {
		return nil, false
	}
	length := int(head[0])
	if prefix == 2 {
		length = int(binary.LittleEndian.Uint16(head))
	}
	return takeBytes(rest, length)
}

func takeBytes(rest *[]byte, length int) ([]byte, bool) {
	if length > len(*rest) {
		return nil, false
	}
	head := (*rest)[:length]
	*rest = (*rest)[length:]
	return head, true
}
