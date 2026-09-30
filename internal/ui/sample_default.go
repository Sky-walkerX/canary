//go:build !uidev

package ui

// watermark is empty in the default build. Only a build with the uidev tag
// carries sample data, and every page it renders says so.
const watermark = ""
