module github.com/larivierec/aws-es-proxy

go 1.23.0

toolchain go1.24.4

require (
	github.com/aws/aws-sdk-go-v2 v1.36.3
	github.com/aws/aws-sdk-go-v2/config v1.29.15
	github.com/aws/aws-sdk-go-v2/credentials v1.17.68
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.20
	github.com/sirupsen/logrus v1.9.3
	go.mongodb.org/mongo-driver/v2 v2.2.2
	golang.org/x/net v0.41.0
)

require (
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.30 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.34 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.34 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.15 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.25.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.30.1 // indirect
	github.com/aws/smithy-go v1.22.2 // indirect
	golang.org/x/sys v0.33.0 // indirect
)
