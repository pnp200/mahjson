# MahJson SDK for Go language
>Package mahjson provides implementation of e-pay POS to Host JSON web services.

## Installing

To start using mahjson, install Go and run `go get`:

```sh
$ go get -u github.com/pnp200/mahjson
```

This will retrieve the library.


## Example
```go
package main

import (
	"fmt"
	"github.com/pnp200/mahjson"
)

func main() {
	url := "your test url"
	publicKey := "your assigned public key"
	privateKey := "your private key"

	// Online PIN
	pin, err := mahjson.NewClient(url, publicKey, privateKey)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	pin.Amount = 5.00
	pin.MerchantID = "201914"
	pin.OperatorID = "SALE"
	pin.TerminalID = "10000494"
	pin.ProductCode = "TUNETALKST"
	pin.TxnTraceID = 118205
	pinResponse, err := pin.OnlinePIN()
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(pinResponse)
}
```

## Implement methods
- [NetworkCheck](https://sandbox.ghlapps.com/apidoc/#api-Network)
- [OnlinePIN](https://sandbox.ghlapps.com/apidoc/#api-PIN-onlinePIN)
- [onlinePINReversal](https://sandbox.ghlapps.com/apidoc/#api-PIN-onlinePINReversal)
- [OnlinePINVoid](https://sandbox.ghlapps.com/apidoc/#api-PIN-onlinePINVoid)
- [Etopup](https://sandbox.ghlapps.com/apidoc/#api-ETopup-etopup)
- [etopupReversal](https://sandbox.ghlapps.com/apidoc/#api-ETopup-etopupReversal)
- [EtopupVoid](https://sandbox.ghlapps.com/apidoc/#api-ETopup-etopupVoid)
- [EtopupAccountInquiry](https://sandbox.ghlapps.com/apidoc/#api-ETopup-etopupAccountInquiry)
- [EtopupTxnUpload](https://sandbox.ghlapps.com/apidoc/#api-ETopup-etopupTxnUpload)
- [Payment](https://sandbox.ghlapps.com/apidoc/#api-Payment-payment)
- [paymentReversal](https://sandbox.ghlapps.com/apidoc/#api-Payment-paymentReversal)
- [PaymentVoid](https://sandbox.ghlapps.com/apidoc/#api-Payment-paymentVoid)
- [PaymentRefund](https://sandbox.ghlapps.com/apidoc/#api-Payment-paymentRefund)
- [PaymentSeamless](https://sandbox.ghlapps.com/apidoc/#api-Payment-seamlessPayment)
- [paymentSeamlessReversal](https://sandbox.ghlapps.com/apidoc/#api-Payment-seamlessReversal)
- [PaymentSeamlessVoid](https://sandbox.ghlapps.com/apidoc/#api-Payment-seamlessPaymentVoid)
- [PaymentSeamlessRefund](https://sandbox.ghlapps.com/apidoc/#api-Payment-seamlessPaymentRefund)
- [PaymentAsynchronous](https://sandbox.ghlapps.com/apidoc/#api-Payment-asynchronousPayment)
- [PaymentQuery](https://sandbox.ghlapps.com/apidoc/#api-Payment-paymentQuery)
- [PaymentTxnUpload](https://sandbox.ghlapps.com/apidoc/#api-Payment-paymentTxnupload)

## Documentation
[Documentation](https://sandbox.ghlapps.com/apidoc/)
