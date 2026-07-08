package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func mockReadDirNamedFile(dirPath string) ([]string, error) {
	return []string{"http-8080.yaml"}, nil
}

// The validator groups findings per source file via Filename, so the loader must
// stamp each service with the file it was read from.
func TestReadConfigurationsServices_StampsFilename(t *testing.T) {
	p := Init("", "")
	p.readFileBytesByFilePathDependency = mockReadfilebytesBeelzebubServiceConfiguration
	p.gelAllFilesNameByDirNameDependency = mockReadDirNamedFile

	services, err := p.ReadConfigurationsServices()
	assert.Nil(t, err)
	assert.Equal(t, "http-8080.yaml", services[0].Filename)
}
