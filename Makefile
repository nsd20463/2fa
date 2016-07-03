GOBIN=$(HOME)/bin

$(GOBIN)/2fa : 2fa.go
	GOBIN="$(GOBIN)" go install
