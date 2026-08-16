// Package bondframe определяет протокол кадрирования multi-lane VLESS bond (Hello, Data, FIN фреймы).
package bondframe

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"time"
)

const (
	Version uint8 = 1
	Magic         = "VLB1"

	FrameData byte = 1
	FrameFIN  byte = 2

	MaxChunk = 16 * 1024

	LaneAttachTimeout = 300 * time.Millisecond
)

// Hello содержит заголовок рукопожатия отдельного lane.
type Hello struct {
	ConnID    uint64
	LaneIndex uint16
	LaneCount uint16
}

// Frame представляет единичный фрейм данных или FIN с последовательным номером Seq.
type Frame struct {
	Type byte
	Seq  uint64
	Data []byte
}

func WriteHello(w io.Writer, connID uint64, laneIndex, laneCount uint16) error {
	var hdr [17]byte
	copy(hdr[0:4], Magic)
	hdr[4] = Version
	binary.BigEndian.PutUint64(hdr[5:13], connID)
	binary.BigEndian.PutUint16(hdr[13:15], laneIndex)
	binary.BigEndian.PutUint16(hdr[15:17], laneCount)
	_, err := w.Write(hdr[:])
	return err
}

// ReadHelloAfterMagic читает остаток заголовка Hello после проверки magic-байтов.
func ReadHelloAfterMagic(r io.Reader, magic [4]byte) (Hello, error) {
	var hdr [17]byte
	copy(hdr[0:4], magic[:])
	if _, err := io.ReadFull(r, hdr[4:]); err != nil {
		return Hello{}, err
	}
	return ParseHelloHeader(hdr[:])
}

func ParseHelloHeader(hdr []byte) (Hello, error) {
	if len(hdr) != 17 {
		return Hello{}, fmt.Errorf("bad bond hello size: %d", len(hdr))
	}
	if string(hdr[0:4]) != Magic {
		return Hello{}, fmt.Errorf("bad bond magic")
	}
	if hdr[4] != Version {
		return Hello{}, fmt.Errorf("unsupported bond version: %d", hdr[4])
	}
	return Hello{
		ConnID:    binary.BigEndian.Uint64(hdr[5:13]),
		LaneIndex: binary.BigEndian.Uint16(hdr[13:15]),
		LaneCount: binary.BigEndian.Uint16(hdr[15:17]),
	}, nil
}

func WriteFrame(w io.Writer, typ byte, seq uint64, data []byte) error {
	if uint64(len(data)) > math.MaxUint32 {
		return fmt.Errorf("bondframe: data too large: %d", len(data))
	}
	var hdr [13]byte
	hdr[0] = typ
	binary.BigEndian.PutUint64(hdr[1:9], seq)
	binary.BigEndian.PutUint32(hdr[9:13], uint32(len(data))) //nolint:gosec // bounded above
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	_, err := w.Write(data)
	return err
}

func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [13]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	size := binary.BigEndian.Uint32(hdr[9:13])
	if size > MaxChunk {
		return Frame{}, fmt.Errorf("bond frame too large: %d", size)
	}
	f := Frame{
		Type: hdr[0],
		Seq:  binary.BigEndian.Uint64(hdr[1:9]),
	}
	if size > 0 {
		f.Data = make([]byte, size)
		if _, err := io.ReadFull(r, f.Data); err != nil {
			return Frame{}, err
		}
	}
	return f, nil
}

// PendingCap ограничивает максимальное число неупорядоченных фреймов в буфере.
const PendingCap = 1024

// ReorderHooks задаёт колбэки для обработки ошибок и событий Reorder.
type ReorderHooks struct {
	OnOverflow    func(have int)
	OnUnknownType func(typ byte)
	OnWriteError  func(err error)
	OnCloseWrite  func(format string, v ...any)
}

// Reorder переупорядочивает фреймы по возрастанию Seq и записывает полезную нагрузку в dst.
func Reorder(ctx context.Context, dst net.Conn, recv <-chan Frame, h ReorderHooks) uint64 {
	pending := make(map[uint64][]byte)
	var expect uint64
	var finSeq *uint64

	for {
		if finSeq != nil && expect == *finSeq {
			CloseWrite(dst, h.OnCloseWrite)
			return expect
		}
		select {
		case <-ctx.Done():
			return expect
		case f, ok := <-recv:
			if !ok {
				return expect
			}
			switch f.Type {
			case FrameData:
				if len(pending) >= PendingCap {
					if h.OnOverflow != nil {
						h.OnOverflow(len(pending))
					}
					return expect
				}
				pending[f.Seq] = f.Data
			case FrameFIN:
				v := f.Seq
				if finSeq == nil || v < *finSeq {
					finSeq = &v
				}
			default:
				if h.OnUnknownType != nil {
					h.OnUnknownType(f.Type)
				}
				return expect
			}
			for {
				data, ok := pending[expect]
				if !ok {
					break
				}
				delete(pending, expect)
				if len(data) > 0 {
					if _, err := dst.Write(data); err != nil {
						if h.OnWriteError != nil {
							h.OnWriteError(err)
						}
						return expect
					}
				}
				expect++
			}
		}
	}
}

// CloseWrite закрывает канал записи conn, если соединение поддерживает half-close.
func CloseWrite(conn net.Conn, errf func(format string, v ...any)) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		if err := cw.CloseWrite(); err != nil && errf != nil {
			errf("CloseWrite failed: %v", err)
		}
	}
}
