module readytrader-crypto/mpc_signer

go 1.24.0

require (
	github.com/coinbase/cb-mpc/demos-go/cb-mpc-go v0.0.0
	golang.org/x/crypto v0.46.0
)

require (
	golang.org/x/sync v0.15.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
)

replace github.com/coinbase/cb-mpc/demos-go/cb-mpc-go => ../vendor/cb-mpc/demos-go/cb-mpc-go
