module github.com/larivierec/aws-es-proxy

go 1.23.0

toolchain go1.24.1

require (
	github.com/aws/aws-sdk-go-v2 v1.36.3
	github.com/aws/aws-sdk-go-v2/config v1.29.11
	github.com/aws/aws-sdk-go-v2/credentials v1.17.64
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.17
	github.com/sirupsen/logrus v1.9.3
	go.mongodb.org/mongo-driver/v2 v2.1.0
	golang.org/x/net v0.37.0
)

require (
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.30 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.34 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.34 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.15 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.25.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.29.2 // indirect
	github.com/aws/smithy-go v1.22.2 // indirect
	golang.org/x/sys v0.31.0 // indirect
)
