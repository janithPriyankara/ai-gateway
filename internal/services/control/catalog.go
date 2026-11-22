package control

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/mcp-gateway/mcp-gateway/internal/domain"
)

//go:embed catalog/*.yaml
var catalogFS embed.FS

// CatalogEntry is a server preset (CTL-005). Community contributions add YAML files.
type CatalogEntry struct {
	Description string        `yaml:"description" json:"description"`
	Docs        string        `yaml:"docs" json:"docs,omitempty"`
	Server      domain.Server `yaml:"server" json:"server"`
	Rules       []domain.Rule `yaml:"rules" json:"rules"`
}

// Catalog returns the embedded catalog sorted by name.
func Catalog() ([]CatalogEntry, error) {
	files, err := fs.Glob(catalogFS, "catalog/*.yaml")
	if err != nil {
		return nil, err
	}
	out := make([]CatalogEntry, 0, len(files))
	for _, f := range files {
		b, err := catalogFS.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var e CatalogEntry
		if err := yaml.Unmarshal(b, &e); err != nil {
			return nil, fmt.Errorf("catalog %s: %w", f, err)
		}
		e.Server = normalizeServer(e.Server)
		e.Server.Enabled = true
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Server.Name < out[j].Server.Name })
	return out, nil
}
