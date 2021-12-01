module github.com/aquasecurity/trivy-plugin-aqua

go 1.16

require (
	github.com/aquasecurity/fanal v0.0.0-20211130145558-2c76718ef52e
	github.com/aquasecurity/go-dep-parser v0.0.0-20211110174639-8257534ffed3
	github.com/aquasecurity/trivy v0.21.1
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v1.2.1
	github.com/stretchr/testify v1.7.0
	github.com/twitchtv/twirp v8.1.1+incompatible
	github.com/urfave/cli/v2 v2.3.0
	go.uber.org/zap v1.19.1
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1
	google.golang.org/protobuf v1.27.1
)