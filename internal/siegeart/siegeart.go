// Package siegeart holds the siege drawing script shared by the admin
// dashboard and the optional public siege page, so both draw the same wall.
package siegeart

import _ "embed"

// JS is siege-art.js. It defines window.SiegeArt and has no dependencies.
//
//go:embed siege-art.js
var JS string
