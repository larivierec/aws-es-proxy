package main

import (
	"testing"
)

func TestValidateRawPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{

		{"root path", "/", false},
		{"simple index", "/my-index", false},
		{"cat api", "/_cat/indices", false},
		{"nested path", "/my-index/_search", false},
		{"date index", "/logs-2024.01.01", false},
		{"wildcard", "/logs-*/_search", false},
		{"underscore", "/my_index", false},
		{"plugin path", "/_plugin/kibana/app/kibana", false},

		{"path traversal", "/../../../etc/passwd", true},
		{"null byte", "/index%00", true},
		{"newline lowercase", "/index%0a", true},
		{"newline uppercase", "/index%0A", true},
		{"carriage return lowercase", "/index%0d", true},
		{"carriage return uppercase", "/index%0D", true},
		{"backslash", "/index\\..\\admin", true},
		{"double encoding", "/index%252e%252e", true},

		{"at symbol", "/index@evil.com", true},
		{"empty path", "", true},
		{"no leading slash", "index", true},
		{"control character", "/index\x00", true},
		{"excessive length", "/" + string(make([]byte, 2049)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRawPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRawPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestValidateRawQuery(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		wantErr bool
	}{

		{"empty query", "", false},
		{"simple param", "v", false},
		{"key-value", "size=10", false},
		{"multiple params", "size=10&from=0", false},
		{"filter path", "filter_path=hits.hits._source", false},
		{"url encoded space", "q=test%20query", false},

		{"null byte", "param=value%00", true},
		{"newline lowercase", "param=value%0a", true},
		{"newline uppercase", "param=value%0A", true},
		{"carriage return lowercase", "param=value%0d", true},
		{"carriage return uppercase", "param=value%0D", true},

		{"at symbol", "user@evil.com", true},
		{"html tag open", "param=<script>", true},
		{"html tag close", "param=</script>", true},
		{"control character", "param=value\x00", true},
		{"excessive length", string(make([]byte, 8193)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRawQuery(tt.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRawQuery(%q) error = %v, wantErr %v", tt.query, err, tt.wantErr)
			}
		})
	}
}

func TestValidateCleanedPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{

		{"root", "/", false},
		{"simple", "/index", false},
		{"nested", "/index/_search", false},
		{"with dash", "/my-index", false},
		{"with underscore", "/my_index", false},
		{"with dot", "/my.index", false},
		{"with asterisk", "/logs-*", false},
		{"cat api", "/_cat/indices", false},

		{"no leading slash", "index", true},
		{"path traversal", "/index/../admin", true},

		{"backslash", "/index\\search", true},
		{"invalid char @", "/index@name", true},
		{"invalid char #", "/index#name", true},
		{"invalid char ?", "/index?query", true},
		{"invalid char =", "/index=name", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCleanedPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCleanedPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}
