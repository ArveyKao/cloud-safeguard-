// Package web embeds the compiled web console into the csg binary.
//
// The console is a Vite/React single-page app built into ./dist by
// `make web` (or `npm run build` inside web/). The committed placeholder
// dist/index.html keeps `go test ./...` building before the console is built;
// `make build` always rebuilds the console first.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var content embed.FS

// FS returns the embedded dashboard filesystem rooted at dist/.
func FS() fs.FS {
	sub, err := fs.Sub(content, "dist")
	if err != nil {
		panic("web: embedded dist is missing: " + err.Error())
	}
	return sub
}
