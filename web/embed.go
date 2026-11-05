// Package web embeds the built UI so the app ships as a single binary.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:static
var files embed.FS

// Static returns the UI files rooted at web/static.
func Static() fs.FS {
	sub, err := fs.Sub(files, "static")
	if err != nil {
		panic(err)
	}
	return sub
}
