package main

import (
	"bytes"
	"fmt"
	"html"
	"html/template"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	east "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"

	"github.com/Sky-walkerX/canary/internal/ui/wording"
)

// docView is one page rendered from a Markdown file in docs/.
type docView struct {
	Title      string
	Body       template.HTML
	TOC        []tocItem
	Source     string
	SourcePath string
}

type tocItem struct {
	ID, Text string
}

// sitePages maps a doc file to the site address that renders it.
var sitePages = map[string]string{
	"docs/how-canary-works.md": "/how-it-works/",
	"docs/faq.md":              "/faq/",
	"docs/glossary.md":         "/glossary/",
}

// docLink rewrites a link from a doc for the site. Links to another rendered
// doc point at its page. Links to other repository files point at the
// repository. Any other outside address returns "", and the caller keeps only
// the link's text, because the site links nowhere but its own pages and the
// repository.
func (s *site) docLink(dest string) (string, error) {
	switch {
	case strings.HasPrefix(dest, "#"):
		return dest, nil
	case strings.HasPrefix(dest, s.cfg.Repo+"/"), dest == s.cfg.Repo:
		return dest, nil
	case strings.Contains(dest, "://"), strings.HasPrefix(dest, "mailto:"), strings.HasPrefix(dest, "//"):
		return "", nil
	}
	file, frag, _ := strings.Cut(dest, "#")
	if frag != "" {
		frag = "#" + frag
	}
	rel := path.Clean(path.Join("docs", file))
	if strings.HasPrefix(rel, "../") {
		return "", fmt.Errorf("site: link %q leaves the repository", dest)
	}
	if p, ok := sitePages[rel]; ok {
		return p + frag, nil
	}
	if _, err := os.Stat(filepath.Join(repoRoot(s.cfg.Docs), filepath.FromSlash(rel))); err != nil {
		return "", fmt.Errorf("site: link %q: no file %s in the repository", dest, rel)
	}
	return s.cfg.Repo + "/blob/main/" + rel + frag, nil
}

// rawBlock is a block of HTML the generator made, such as a drawing or a
// jump list. It renders as is.
type rawBlock struct {
	ast.BaseBlock
	html []byte
}

var kindRawBlock = ast.NewNodeKind("CanaryRawBlock")

func (n *rawBlock) Kind() ast.NodeKind            { return kindRawBlock }
func (n *rawBlock) Dump(source []byte, level int) { ast.DumpHelper(n, source, level, nil, nil) }

type rawBlockRenderer struct{}

func (rawBlockRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(kindRawBlock, func(w util.BufWriter, _ []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
		if entering {
			w.Write(n.(*rawBlock).html)
			w.WriteByte('\n')
		}
		return ast.WalkSkipChildren, nil
	})
}

func rawInline(s string) *ast.String {
	n := ast.NewString([]byte(s))
	n.SetCode(true)
	return n
}

var md = goldmark.New(
	goldmark.WithExtensions(extension.Table),
	goldmark.WithParserOptions(parser.WithAutoHeadingID()),
	goldmark.WithRendererOptions(renderer.WithNodeRenderers(util.Prioritized(rawBlockRenderer{}, 100))),
)

// plainText returns the visible text under n.
func plainText(n ast.Node, src []byte) string {
	var b strings.Builder
	ast.Walk(n, func(c ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch t := c.(type) {
		case *ast.Text:
			b.Write(t.Segment.Value(src))
			if t.SoftLineBreak() || t.HardLineBreak() {
				b.WriteByte(' ')
			}
		case *ast.String:
			b.Write(t.Value)
		}
		return ast.WalkContinue, nil
	})
	return b.String()
}

// renderDoc turns one doc into a page body. It takes the first h1 as the
// page title, draws each Mermaid diagram, rewrites links, turns the docs'
// lists of in-page links into jump lists, and shows each state label that
// fills a table cell as a state badge.
func (s *site) renderDoc(name string, src []byte) (docView, error) {
	doc := md.Parser().Parse(text.NewReader(src))
	var v docView
	badges, err := s.stateBadges()
	if err != nil {
		return v, err
	}

	type swap struct{ old, new ast.Node }
	var swaps []swap
	var drop []ast.Node
	var tableLabels []string
	lastHeading := ""
	var walkErr error

	ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch n := n.(type) {
		case *ast.Heading:
			txt := strings.TrimSpace(plainText(n, src))
			id := ""
			if v, ok := n.AttributeString("id"); ok {
				if b, ok := v.([]byte); ok {
					id = string(b)
				}
			}
			switch {
			case n.Level == 1 && v.Title == "":
				v.Title = txt
				drop = append(drop, n)
				return ast.WalkSkipChildren, nil
			case n.Level == 2:
				v.TOC = append(v.TOC, tocItem{ID: id, Text: txt})
			}
			lastHeading = txt
		case *ast.FencedCodeBlock:
			if string(n.Language(src)) != "mermaid" {
				return ast.WalkContinue, nil
			}
			var body bytes.Buffer
			for i := 0; i < n.Lines().Len(); i++ {
				seg := n.Lines().At(i)
				body.Write(seg.Value(src))
			}
			d, err := drawing(s.parts, body.String())
			if err != nil {
				walkErr = fmt.Errorf("site: %s: %w", name, err)
				return ast.WalkStop, nil
			}
			swaps = append(swaps, swap{n, &rawBlock{html: []byte(d)}})
		case *ast.Paragraph:
			if j, ok := jumpList(n, src); ok {
				swaps = append(swaps, swap{n, &rawBlock{html: []byte(j)}})
				return ast.WalkSkipChildren, nil
			}
		case *ast.Link:
			href, err := s.docLink(string(n.Destination))
			if err != nil {
				walkErr = fmt.Errorf("%w (in %s)", err, name)
				return ast.WalkStop, nil
			}
			if href == "" {
				swaps = append(swaps, swap{n, rawInline(html.EscapeString(plainText(n, src)))})
				return ast.WalkSkipChildren, nil
			}
			n.Destination = []byte(href)
		case *east.Table:
			tableLabels = append(tableLabels, lastHeading)
		case *east.TableCell:
			if b, ok := badges[strings.TrimSpace(plainText(n, src))]; ok {
				n.RemoveChildren(n)
				n.AppendChild(n, rawInline(b))
				return ast.WalkSkipChildren, nil
			}
		}
		return ast.WalkContinue, nil
	})
	if walkErr != nil {
		return v, walkErr
	}
	if v.Title == "" {
		return v, fmt.Errorf("site: %s has no h1 to title its page", name)
	}
	for _, n := range drop {
		n.Parent().RemoveChild(n.Parent(), n)
	}
	for _, sw := range swaps {
		sw.old.Parent().ReplaceChild(sw.old.Parent(), sw.old, sw.new)
	}
	mergeJumpLists(doc)

	var out bytes.Buffer
	if err := md.Renderer().Render(&out, src, doc); err != nil {
		return v, fmt.Errorf("site: render %s: %w", name, err)
	}
	v.Body = template.HTML(wrapTables(out.String(), tableLabels))
	return v, nil
}

// stateBadges renders the state badge for each of the six labels.
func (s *site) stateBadges() (map[string]string, error) {
	out := map[string]string{}
	for _, st := range wording.States() {
		var b bytes.Buffer
		if err := s.parts.ExecuteTemplate(&b, "stateBadge", st); err != nil {
			return nil, fmt.Errorf("site: render state badge: %w", err)
		}
		out[st.Label] = b.String()
	}
	return out, nil
}

// jumpList recognises a paragraph that is only in-page links separated by
// middle dots, optionally led by a bold label ending in a colon, and returns
// it as a labelled list.
func jumpList(p *ast.Paragraph, src []byte) (string, bool) {
	label := ""
	var links []string
	for c := p.FirstChild(); c != nil; c = c.NextSibling() {
		switch c := c.(type) {
		case *ast.Emphasis:
			if c.Level != 2 || label != "" || len(links) > 0 {
				return "", false
			}
			label = strings.TrimSuffix(strings.TrimSpace(plainText(c, src)), ":")
		case *ast.Link:
			dest := string(c.Destination)
			if !strings.HasPrefix(dest, "#") {
				return "", false
			}
			links = append(links, fmt.Sprintf(`<li><a href="%s">%s</a></li>`,
				html.EscapeString(dest), html.EscapeString(plainText(c, src))))
		case *ast.Text:
			if t := strings.TrimSpace(string(c.Segment.Value(src))); t != "" && t != "·" {
				return "", false
			}
		default:
			return "", false
		}
	}
	if len(links) < 3 {
		return "", false
	}
	var b strings.Builder
	b.WriteString(`<div class="jump">`)
	if label != "" {
		fmt.Fprintf(&b, `<p class="jump-label">%s</p>`, html.EscapeString(label))
	}
	b.WriteString(`<ul class="jump-list">` + strings.Join(links, "") + `</ul></div>`)
	return b.String(), true
}

// mergeJumpLists puts neighbouring jump lists in one navigation block, so the
// FAQ's four groups read as one index.
func mergeJumpLists(doc ast.Node) {
	for c := doc.FirstChild(); c != nil; c = c.NextSibling() {
		first, ok := c.(*rawBlock)
		if !ok || !bytes.HasPrefix(first.html, []byte(`<div class="jump">`)) {
			continue
		}
		group := []byte(`<nav class="jump-set" aria-label="` + html.EscapeString(wording.Site.OnThisPage) + `">`)
		group = append(group, first.html...)
		for {
			next, ok := first.NextSibling().(*rawBlock)
			if !ok || !bytes.HasPrefix(next.html, []byte(`<div class="jump">`)) {
				break
			}
			group = append(group, next.html...)
			doc.RemoveChild(doc, next)
		}
		first.html = append(group, "</nav>"...)
	}
}

var tableOpen = regexp.MustCompile(`<table>`)

// wrapTables puts each table in a labelled container that scrolls on its own,
// so a wide table never makes the page scroll sideways.
func wrapTables(body string, labels []string) string {
	i := 0
	body = tableOpen.ReplaceAllStringFunc(body, func(string) string {
		heading := ""
		if i < len(labels) {
			heading = labels[i]
		}
		label := wording.Site.TableLabel(heading)
		i++
		return `<div class="table-wrap doc-table" role="region" tabindex="0" aria-label="` + html.EscapeString(label) + `"><table>`
	})
	return strings.ReplaceAll(body, "</table>", "</table></div>")
}
