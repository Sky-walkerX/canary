package ui

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed assets
var assetFS embed.FS

// pageNames are the page templates. Each one defines "content" and is parsed
// on its own copy of the layout and partials.
var pageNames = []string{"overview", "blocks", "block", "findings", "finding", "error"}

var pages = mustParsePages()

func mustParsePages() map[string]*template.Template {
	base := template.Must(template.New("base").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/partials.html"))
	out := map[string]*template.Template{}
	for _, name := range pageNames {
		t := template.Must(template.Must(base.Clone()).ParseFS(templateFS, "templates/"+name+".html"))
		out[name] = t
	}
	return out
}

// sprite is glyphs.svg, inlined once at the top of every page so each
// glyph and icon is a same-document <use> reference.
var sprite = mustSprite()

func mustSprite() template.HTML {
	b, err := fs.ReadFile(assetFS, "assets/glyphs.svg")
	if err != nil {
		panic(err)
	}
	// Drop the XML prolog and comments before inlining.
	s := string(b)
	if i := strings.Index(s, "<svg"); i > 0 {
		s = s[i:]
	}
	return template.HTML(s)
}

type asset struct {
	body        []byte
	contentType string
	etag        string
}

var assets = mustLoadAssets()

var contentTypes = map[string]string{
	".css":   "text/css; charset=utf-8",
	".js":    "text/javascript; charset=utf-8",
	".svg":   "image/svg+xml",
	".woff2": "font/woff2",
	".txt":   "text/plain; charset=utf-8",
}

func mustLoadAssets() map[string]asset {
	out := map[string]asset{}
	err := fs.WalkDir(assetFS, "assets", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		ct, ok := contentTypes[path.Ext(p)]
		if !ok {
			return nil
		}
		b, err := fs.ReadFile(assetFS, p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		out[strings.TrimPrefix(p, "assets/")] = asset{body: b, contentType: ct, etag: `"` + hex.EncodeToString(sum[:8]) + `"`}
		return nil
	})
	if err != nil {
		panic(err)
	}
	return out
}

func serveAsset(w http.ResponseWriter, r *http.Request) {
	serveAssetNamed(w, r, r.PathValue("file"))
}

// serveAssetNamed serves one embedded asset. Only files present at build
// time exist, so no request can name anything else. Browsers revalidate each
// asset by its content hash, which keeps an upgraded binary's files fresh.
func serveAssetNamed(w http.ResponseWriter, r *http.Request, name string) {
	a, ok := assets[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", a.contentType)
	h.Set("Cache-Control", "no-cache")
	h.Set("ETag", a.etag)
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(a.body))
}
