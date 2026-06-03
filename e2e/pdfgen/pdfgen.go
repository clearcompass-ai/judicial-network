// Package pdfgen generates valid, blank test PDFs of a controllable byte size.
//
// It is built for high-fan-out test workloads: sizing uses crypto/rand (no global
// math/rand mutex, which would bottleneck generation across many goroutines prior
// to Go 1.22) and a functional-options API so a caller can pass no bounds, just a
// minimum, just a maximum, or both. Used by the baseproof e2e suite to drive
// artifact-bearing flows (PDF generation lands once #89 is implemented).
package pdfgen

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
)

// config holds the sizing rules for a generated PDF.
type config struct {
	minSize int
	maxSize int
	hasMin  bool
	hasMax  bool
}

// Option configures PDF generation.
type Option func(*config)

// WithMinSize sets the minimum byte size for the PDF.
func WithMinSize(size int) Option {
	return func(c *config) {
		c.minSize = size
		c.hasMin = true
	}
}

// WithMaxSize sets the maximum byte size for the PDF.
func WithMaxSize(size int) Option {
	return func(c *config) {
		c.maxSize = size
		c.hasMax = true
	}
}

// GenerateBatch creates count PDFs. Each call to GenerateTestPDF is independent and
// goroutine-safe (crypto/rand carries no shared lock), so a caller may fan this out
// across goroutines when generating very large batches.
func GenerateBatch(count int, opts ...Option) [][]byte {
	batch := make([][]byte, count)
	for i := 0; i < count; i++ {
		batch[i] = GenerateTestPDF(opts...)
	}
	return batch
}

// GenerateTestPDF creates a single valid, blank PDF. Size logic:
//   - Both min & max: a random size in [min, max].
//   - Only min OR only max: that size (approximately — within the fixed trailer
//     overhead).
//   - Neither: the smallest valid PDF (~250 bytes).
func GenerateTestPDF(opts ...Option) []byte {
	cfg := &config{}
	for _, opt := range opts {
		opt(cfg)
	}

	targetSizeBytes := 0
	switch {
	case cfg.hasMin && cfg.hasMax && cfg.maxSize > cfg.minSize:
		// Thread-safe random size, no shared mutex.
		diff := int64(cfg.maxSize - cfg.minSize + 1)
		n, _ := rand.Int(rand.Reader, big.NewInt(diff))
		targetSizeBytes = cfg.minSize + int(n.Int64())
	case cfg.hasMax:
		targetSizeBytes = cfg.maxSize
	case cfg.hasMin:
		targetSizeBytes = cfg.minSize
	}

	var buf bytes.Buffer
	offsets := make(map[int]int)

	writeObj := func(id int, content string) {
		offsets[id] = buf.Len()
		buf.WriteString(fmt.Sprintf("%d 0 obj\n%s\nendobj\n", id, content))
	}

	// 1. Header.
	buf.WriteString("%PDF-1.4\n%\xE2\xE3\xCF\xD3\n")

	// 2. Base objects.
	writeObj(1, "<< /Type /Catalog /Pages 2 0 R >>")
	writeObj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	writeObj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")

	// 3. Padding stream sized to hit the target.
	overhead := buf.Len() + 250 // rough estimate of the obj-4 wrapper + xref + trailer
	padSize := targetSizeBytes - overhead
	if padSize < 0 {
		padSize = 0
	}
	offsets[4] = buf.Len()
	buf.WriteString(fmt.Sprintf("4 0 obj\n<< /Length %d >>\nstream\n", padSize))
	buf.Write(bytes.Repeat([]byte("0"), padSize))
	buf.WriteString("\nendstream\nendobj\n")

	// 4. Xref table.
	xrefOffset := buf.Len()
	buf.WriteString("xref\n0 5\n0000000000 65535 f \n")
	for i := 1; i <= 4; i++ {
		buf.WriteString(fmt.Sprintf("%010d 00000 n \n", offsets[i]))
	}

	// 5. Trailer.
	buf.WriteString(fmt.Sprintf("trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", xrefOffset))

	return buf.Bytes()
}
