package main

import (
	"MahJson/src/ghl.com/mahjson"
	"fmt"
)

func main() {
	// // Network Check
	// var net = mahjson.API{}
	// netCheck, err := net.NetworkCheck()
	// if err != nil {
	// 	fmt.Println(err.Error())
	// }
	// fmt.Println(netCheck)

	// Online PIN
	pin := mahjson.API{}
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
	// time.Sleep(time.Second) // don't do void immediately after sale
	// pinVoidResponse, err := pin.OnlinePINVoid(gjson.Get(pinResponse, "msg.TxnRef").String())
	// if err != nil {
	// 	fmt.Println(err.Error())
	// }
	// fmt.Println(pinVoidResponse)

	// // E-Topup
	// etu := mahjson.API{}
	// etu.Amount = 10.00
	// etu.MerchantID = "201914"
	// etu.OperatorID = "SALE"
	// etu.TerminalID = "10000494"
	// etu.ProductCode = "TUNETALKST"
	// etu.AccountNo = "0812345678"
	// etu.TxnTraceID = 118205
	// etuResponse, err := etu.Etopup()
	// if err != nil {
	// 	fmt.Println(err.Error())
	// }
	// fmt.Println(etuResponse)
	// time.Sleep(time.Second) // don't do void immediately after sale
	// etuVoidResponse, err := etu.EtopupVoid(gjson.Get(etuResponse, "msg.TxnRef").String())
	// if err != nil {
	// 	fmt.Println(err.Error())
	// }
	// fmt.Println(etuVoidResponse)
	// // TxnUpload
	// etu.ProductCode = "TNGRELOAD"
	// etuUpload, err := etu.EtopupTxnUpload("123")
	// if err != nil {
	// 	fmt.Println(err.Error())
	// }
	// fmt.Println(etuUpload)
	//
	// // Payment
	// pmt := mahjson.API{}
	// pmt.Amount = 20.00
	// pmt.MerchantID = "201914"
	// pmt.OperatorID = "SALE"
	// pmt.TerminalID = "10000494"
	// pmt.ProductCode = "BOOST"
	// pmt.AccountNo = "0812345678"
	// pmt.TxnTraceID = 118205
	// pmtResponse, err := pmt.Payment()
	// if err != nil {
	// 	fmt.Println(err.Error())
	// }
	// fmt.Println(pmtResponse)
	// time.Sleep(time.Second) // don't do void immediately after sale
	// pmtVoidResponse, err := pmt.PaymentVoid(gjson.Get(pmtResponse, "msg.TxnRef").String())
	// if err != nil {
	// 	fmt.Println(err.Error())
	// }
	// fmt.Println(pmtVoidResponse)
	// // Seamless Payment
	// pmt.Amount = 30.00
	// pmt.AccountNo = "800123456789055555"
	// seamless, err := pmt.PaymentSeamless()
	// if err != nil {
	// 	fmt.Println(err.Error())
	// }
	// fmt.Println(seamless)
	// time.Sleep(time.Second) // don't do void immediately after sale
	// seamlessVoid, err := pmt.PaymentSeamlessVoid(gjson.Get(seamless, "msg.TxnRef").String())
	// if err != nil {
	// 	fmt.Println(err.Error())
	// }
	// fmt.Println(seamlessVoid)
	// // Asynchronous Payment
	// pmt.Amount = 40.00
	// pmt.ProductCode = "BOOSTDQR"
	// asynchronous, err := pmt.PaymentAsynchronous()
	// if err != nil {
	// 	fmt.Println(err.Error())
	// }
	// fmt.Println(asynchronous)
	// // TxnUpload
	// pmt.ProductCode = "TNGPAYMENT"
	// pmtUpload, err := pmt.PaymentTxnUpload("123")
	// if err != nil {
	// 	fmt.Println(err.Error())
	// }
	// fmt.Println(pmtUpload)
}
