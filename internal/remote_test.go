package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseFileContent(t *testing.T) {
	parsed := parseFileContent([]byte("aaa\n#bbb\n\nccc"))
	assert.ElementsMatch(t, []string{"aaa", "ccc"}, parsed)
}
