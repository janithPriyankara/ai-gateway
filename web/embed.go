// Package web embeds the built dashboard (web/dist) into the binary (DEP-008).
package web

import "embed"

// Dist holds the built single-page app. `npm run build` in web/ regenerates it.
//
//go:embed all:dist
var Dist embed.FS
