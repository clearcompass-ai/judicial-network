package pdfgen

import (
	"bytes"
	"testing"
)

func wellFormed(t *testing.T, b []byte) {
	t.Helper()
	if !bytes.HasPrefix(b, []byte("%PDF-1.4")) {
		t.Fatalf("missing PDF header; got prefix %q", b[:min(8, len(b))])
	}
	if !bytes.Contains(b, []byte("%%EOF")) {
		t.Fatal("PDF is missing its trailer EOF marker")
	}
	if !bytes.Contains(b, []byte("/Root 1 0 R")) {
		t.Fatal("missing trailer /Root")
	}
}

func TestGenerate_Minimal(t *testing.T) {
	b := GenerateTestPDF()
	wellFormed(t, b)
	if len(b) > 1024 {
		t.Fatalf("minimal PDF is %d bytes, expected the small baseline (~250)", len(b))
	}
}

func TestGenerate_WithinMinMax(t *testing.T) {
	const minB, maxB = 20 * 1024, 64 * 1024
	for i := 0; i < 32; i++ {
		b := GenerateTestPDF(WithMinSize(minB), WithMaxSize(maxB))
		wellFormed(t, b)
		// The target is randomised in [min,max]; final size tracks it within the
		// fixed trailer overhead (~a few hundred bytes), so allow a small slack.
		if len(b) < minB-512 || len(b) > maxB+512 {
			t.Fatalf("size %d outside [%d,%d] (±512 overhead slack)", len(b), minB, maxB)
		}
	}
}

func TestGenerate_OnlyMin_HitsApproxTarget(t *testing.T) {
	const minB = 50 * 1024
	b := GenerateTestPDF(WithMinSize(minB))
	wellFormed(t, b)
	if len(b) < minB-512 || len(b) > minB+512 {
		t.Fatalf("only-min size %d not ~%d (±512)", len(b), minB)
	}
}

func TestGenerate_BiggerTargetBiggerOutput(t *testing.T) {
	small := GenerateTestPDF(WithMinSize(10 * 1024))
	big := GenerateTestPDF(WithMinSize(40 * 1024))
	if len(big) <= len(small) {
		t.Fatalf("expected larger target to yield a larger PDF: small=%d big=%d", len(small), len(big))
	}
}

func TestGenerateBatch_Count(t *testing.T) {
	batch := GenerateBatch(10, WithMaxSize(8*1024))
	if len(batch) != 10 {
		t.Fatalf("batch len = %d, want 10", len(batch))
	}
	for i, b := range batch {
		if len(b) == 0 {
			t.Fatalf("batch[%d] is empty", i)
		}
		wellFormed(t, b)
	}
}
