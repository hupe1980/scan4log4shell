package internal

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHasSuffix(t *testing.T) {
	tests := []struct {
		filename string
		suffix   string
		want     bool
	}{
		{
			filename: "a/b/core/Test.class",
			suffix:   "core/Test.class",
			want:     true,
		},
		{
			filename: "a/b/core/test.class",
			suffix:   "core/Test.class",
			want:     true,
		},
		{
			filename: "a/b/core/Test.class",
			suffix:   "core/test.class",
			want:     true,
		},
		{
			filename: "a/b/corex/Test.class",
			suffix:   "core/test.class",
			want:     false,
		},
		{
			filename: "a/b/core/Test.classx",
			suffix:   "core/test.class",
			want:     false,
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("Test-%d", i), func(t *testing.T) {
			assert.Equal(t, test.want, hasSuffix(test.filename, test.suffix))
		})
	}
}
