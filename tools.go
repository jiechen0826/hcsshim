//go:build tools

package tools

// This file ensures that packages needed by tests are vendored.
// See: https://github.com/go-modules-by-example/index/blob/master/010_tools/README.md

import (
	_ "github.com/containerd/containerd/v2/pkg/oci"
)