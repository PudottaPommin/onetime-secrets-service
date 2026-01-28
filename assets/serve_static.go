//go:build bindata

//go:generate go tool asseter gen -src ./cdn -pkg assets -out bindata.asseter.go

package assets

import (
	"github.com/pudottapommin/golib/pkg/assetsfs"
)

func BuiltinAssets() *assetsfs.Layer {
	return assetsfs.Blobs("builtin(bindata)", Assets)
}

func Url(path string) string {
	return "/static/" + Assets.HashedByPath(path)
}
