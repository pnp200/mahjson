package mahjson_test

import (
	"github.com/pnp200/mahjson"
	"github.com/tidwall/gjson"
	"testing"
	"time"
)

func TestMahJson(t *testing.T) {
	url := "your test url"
	publicKey := "your assigned public key"
	privateKey := "your private key"

	net, err := mahjson.NewClient(url, publicKey, privateKey)
	if err != nil {
		t.Error(err)
		return
	}
	// Network Check
	netCheck, err := net.NetworkCheck()
	if err != nil {
		t.Error(err)
	}
	t.Log(netCheck)

	// Online PIN
	pin, err := mahjson.NewClient(url, publicKey, privateKey)
	if err != nil {
		t.Error(err)
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
		t.Error(err)
	}
	t.Log(pinResponse)
	time.Sleep(time.Second) // don't do void immediately after sale
	pinVoidResponse, err := pin.OnlinePINVoid(gjson.Get(pinResponse, "msg.TxnRef").String())
	if err != nil {
		t.Error(err)
	}
	t.Log(pinVoidResponse)

	// E-Topup
	etu, err := mahjson.NewClient(url, publicKey, privateKey)
	if err != nil {
		t.Error(err)
		return
	}
	etu.Amount = 10.00
	etu.MerchantID = "201914"
	etu.OperatorID = "SALE"
	etu.TerminalID = "10000494"
	etu.ProductCode = "TUNETALKST"
	etu.AccountNo = "0812345678"
	etu.TxnTraceID = 118205
	etuResponse, err := etu.Etopup()
	if err != nil {
		t.Error(err)
	}
	t.Log(etuResponse)
	time.Sleep(time.Second) // don't do void immediately after sale
	etuVoidResponse, err := etu.EtopupVoid(gjson.Get(etuResponse, "msg.TxnRef").String())
	if err != nil {
		t.Error(err)
	}
	t.Log(etuVoidResponse)
	// TxnUpload
	etu.ProductCode = "TNGRELOAD"
	etuUpload, err := etu.EtopupTxnUpload("123")
	if err != nil {
		t.Error(err)
	}
	t.Log(etuUpload)

	// Payment
	pmt, err := mahjson.NewClient(url, publicKey, privateKey)
	if err != nil {
		t.Error(err)
		return
	}
	pmt.Amount = 20.00
	pmt.MerchantID = "201914"
	pmt.OperatorID = "SALE"
	pmt.TerminalID = "10000494"
	pmt.ProductCode = "BOOST"
	pmt.AccountNo = "0812345678"
	pmt.TxnTraceID = 118205
	pmtResponse, err := pmt.Payment()
	if err != nil {
		t.Error(err)
	}
	t.Log(pmtResponse)
	time.Sleep(time.Second) // don't do void immediately after sale
	pmtVoidResponse, err := pmt.PaymentVoid(gjson.Get(pmtResponse, "msg.TxnRef").String())
	if err != nil {
		t.Error(err)
	}
	t.Log(pmtVoidResponse)
	// Seamless Payment
	pmt.Amount = 30.00
	pmt.AccountNo = "800123456789055555"
	seamless, err := pmt.PaymentSeamless()
	if err != nil {
		t.Error(err)
	}
	t.Log(seamless)
	time.Sleep(time.Second) // don't do void immediately after sale
	seamlessVoid, err := pmt.PaymentSeamlessVoid(gjson.Get(seamless, "msg.TxnRef").String())
	if err != nil {
		t.Error(err)
	}
	t.Log(seamlessVoid)
	// Asynchronous Payment
	pmt.Amount = 40.00
	pmt.ProductCode = "BOOSTDQR"
	asynchronous, err := pmt.PaymentAsynchronous()
	if err != nil {
		t.Error(err)
	}
	t.Log(asynchronous)
	// TxnUpload
	pmt.ProductCode = "TNGPAYMENT"
	pmtUpload, err := pmt.PaymentTxnUpload("123")
	if err != nil {
		t.Error(err)
	}
	t.Log(pmtUpload)
}
