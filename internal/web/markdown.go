package web

import (
	"html"
	"regexp"
	"strings"
)

// renderMarkdown converts a subset of Markdown to HTML.
// Supported: paragraphs, headers (# to ###), bold, italic, links, unordered lists.
func renderMarkdown(input string) string {
	if input == "" {
		return ""
	}

	lines := strings.Split(strings.ReplaceAll(input, "\r\n", "\n"), "\n")
	var out strings.Builder
	var inList bool

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		// Empty line closes list
		if trimmed == "" {
			if inList {
				out.WriteString("</ul>")
				inList = false
			}
			continue
		}

		// Unordered list items
		if strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* ") {
			if !inList {
				out.WriteString("<ul>")
				inList = true
			}
			out.WriteString("<li>")
			out.WriteString(inlineMarkdown(html.EscapeString(trimmed[2:])))
			out.WriteString("</li>")
			continue
		}

		// Close list if non-list line follows
		if inList {
			out.WriteString("</ul>")
			inList = false
		}

		// Headers
		if strings.HasPrefix(trimmed, "### ") {
			out.WriteString("<h3>")
			out.WriteString(inlineMarkdown(html.EscapeString(trimmed[4:])))
			out.WriteString("</h3>")
			continue
		}
		if strings.HasPrefix(trimmed, "## ") {
			out.WriteString("<h2>")
			out.WriteString(inlineMarkdown(html.EscapeString(trimmed[3:])))
			out.WriteString("</h2>")
			continue
		}
		if strings.HasPrefix(trimmed, "# ") {
			out.WriteString("<h1>")
			out.WriteString(inlineMarkdown(html.EscapeString(trimmed[2:])))
			out.WriteString("</h1>")
			continue
		}

		// Regular paragraph
		out.WriteString("<p>")
		out.WriteString(inlineMarkdown(html.EscapeString(trimmed)))
		out.WriteString("</p>")
	}

	if inList {
		out.WriteString("</ul>")
	}

	return out.String()
}

var (
	boldRe   = regexp.MustCompile(`\*\*(.+?)\*\*`)
	italicRe = regexp.MustCompile(`\*(.+?)\*`)
	linkRe   = regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`)
	codeRe   = regexp.MustCompile("`([^`]+)`")
)

func inlineMarkdown(s string) string {
	// Links first (before bold/italic processing)
	s = linkRe.ReplaceAllString(s, `<a href="$2">$1</a>`)
	// Code spans
	s = codeRe.ReplaceAllString(s, `<code>$1</code>`)
	// Bold before italic
	s = boldRe.ReplaceAllString(s, `<strong>$1</strong>`)
	s = italicRe.ReplaceAllString(s, `<em>$1</em>`)
	return s
}
