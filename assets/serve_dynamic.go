//go:build !bindata

package assets

import (
	"github.com/pudottapommin/golib/vfs"
)

func BuiltinAssets() *vfs.Layer {
	return vfs.Local("builtin(dynamic)", ".", "assets/cdn")
}

func Url(path string) string {
	return "/static/" + path
}
