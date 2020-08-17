package mahjson

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	jose "github.com/dvsekhvalnov/jose2go"
	"github.com/dvsekhvalnov/jose2go/compact"
	Rsa "github.com/dvsekhvalnov/jose2go/keys/rsa"
	uuid "github.com/satori/go.uuid"
	"github.com/tidwall/gjson"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	Security = "0"
	Version  = "1"
)

type Client struct {
	url         string
	privateKey  *rsa.PrivateKey
	publicKey   *rsa.PublicKey

	msgType     string
	txnType     string
	Amount      float64
	MerchantID  string
	OperatorID  string
	retTxnRef   string
	TerminalID  string
	ProductCode string
	AccountNo   string
	posDateTime string
	TxnTraceID  int
}

// init client
func NewClient(url string, publicKeyFile string, privateKeyFile string) (client *Client, err error) {
	publicKey, err := getPublicKey(publicKeyFile)
	if err != nil {
		return nil, err
	}
	privateKey, err := getPrivateKey(privateKeyFile)
	if err != nil {
		return nil, err
	}
	client = &Client{}
	client.url = url
	client.publicKey = publicKey
	client.privateKey = privateKey

	return client, nil
}

func (this *Client) setMsgType(msgType string) {
	this.msgType = msgType
}

func (this *Client) setTxnType(txnType string) {
	this.txnType = txnType
}

func (this *Client) unsetAccountNo() {
	this.AccountNo = ""
}

func (this *Client) unsetProductCode() {
	this.ProductCode = ""
}

func (this *Client) setRetTxnRef() {
	this.retTxnRef = strings.Replace(uuid.NewV4().String(), "-", "", -1)
}

func (this *Client) setPosDateTime() {
	this.posDateTime = time.Now().Format("20060102150405")
}

func (this *Client) getPayload() string {
	return Security +
		Version +
		this.msgType +
		this.txnType +
		strconv.Itoa(this.TxnTraceID) +
		this.AccountNo +
		this.ProductCode +
		fmt.Sprintf("%.2f", this.Amount) +
		this.MerchantID +
		this.TerminalID +
		this.retTxnRef +
		this.posDateTime
}

func getPublicKey(keyPath string) (*rsa.PublicKey, error) {
	keyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, errors.New("invalid public key file")
	}

	publicKey, err := Rsa.ReadPublic(keyBytes)
	if err != nil {
		return nil, errors.New("invalid public key format")
	}
	return publicKey, nil
}

func getPrivateKey(keyPath string) (*rsa.PrivateKey, error) {
	keyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, errors.New("invalid private key file")
	}

	privateKey, err := Rsa.ReadPrivate(keyBytes)
	if err != nil {
		return nil, errors.New("invalid private key format")
	}
	return privateKey, nil
}

func (this *Client) sign(payload string) (string, error) {
	rng := rand.Reader
	header := []byte(`{"typ":"JWT","alg":"RS256"}`)
	securedInput := []byte(compact.Serialize(header, []byte(payload)))
	hashed := sha256.Sum256(securedInput)
	signature, err := rsa.SignPKCS1v15(rng, this.privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}
	return compact.Serialize(signature), nil
}

func (this *Client) verify(response string) (string, error) {
	if !gjson.Valid(response) || !gjson.Get(response, "security").Exists() || !gjson.Get(response, "version").Exists() ||
		!gjson.Get(response, "msg").Exists() || !gjson.Get(response, "signature").Exists() {
		return "", errors.New(response)
	}
	ref := []string{"security", "version", "msg.MsgType", "msg.TxnType", "msg.TxnTraceID", "msg.AccountNo", "msg.ProductCode", "msg.Amount", "msg.MerchantID", "msg.TerminalID", "msg.RetTxnRef", "msg.POSDateTime", "msg.TxnDateTime", "msg.TxnRef", "msg.ResponseCode", "msg.ResponseMsg"}
	payload := ""
	for _, val := range ref {
		if val == "msg.Amount" {
			payload += gjson.Get(response, val).Raw
		} else {
			payload += gjson.Get(response, val).String()
		}

	}
	securedInput := compact.Serialize([]byte(gjson.Get(response, "signature.parameter").String()), []byte(payload))
	securedInput = securedInput + "." + gjson.Get(response, "signature.value").String()
	_, _, err := jose.Decode(securedInput, this.publicKey)
	if err != nil {
		return "", err
	}

	return response, nil
}

func postJson(url string, jsonData string) (string, error) {
	fmt.Println(jsonData)
	jsonStr := []byte(jsonData)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout: 50 * 1000 * 1000 * 1000,
		}).DialContext,
	}
	client := &http.Client{Transport: transport}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func postJsonTimeout(url string, jsonData string) (string, error) {
	fmt.Println(jsonData)
	jsonStr := []byte(jsonData)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout: 500 * time.Millisecond,
		}).DialContext,
	}
	client := &http.Client{Transport: transport}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func (this *Client) NetworkCheck() (string, error) {
	this.setMsgType("NetworkCheck")
	this.setPosDateTime()
	sign, err := this.sign(this.getPayload())
	if err != nil {
		return "", err
	}
	data := map[string]interface{}{
		"security": Security,
		"version":  Version,
		"msg": map[string]string{
			"MsgType":     this.msgType,
			"POSDateTime": this.posDateTime,
		},
		"signature": map[string]string{
			"type":      "JWT",
			"value":     sign,
			"parameter": "{\"typ\":\"JWT\",\"alg\":\"RS256\"}",
		},
	}
	jsonData, _ := json.Marshal(data)

	return postJson(this.url, string(jsonData))
}

func (this *Client) OnlinePIN() (string, error) {
	this.setMsgType("Sale")
	this.setTxnType("PIN")
	this.unsetAccountNo()
	this.setRetTxnRef()
	this.setPosDateTime()
	sign, err := this.sign(this.getPayload())
	if err != nil {
		return "", err
	}
	data := map[string]interface{}{
		"security": Security,
		"version":  Version,
		"msg": map[string]interface{}{
			"MsgType":     this.msgType,
			"TxnType":     this.txnType,
			"Amount":      fmt.Sprintf("%.2f", this.Amount),
			"MerchantID":  this.MerchantID,
			"OperatorID":  this.OperatorID,
			"RetTxnRef":   this.retTxnRef,
			"TerminalID":  this.TerminalID,
			"ProductCode": this.ProductCode,
			"POSDateTime": this.posDateTime,
			"TxnTraceID":  this.TxnTraceID,
		},
		"signature": map[string]string{
			"type":      "JWT",
			"value":     sign,
			"parameter": "{\"typ\":\"JWT\",\"alg\":\"RS256\"}",
		},
	}
	jsonData, _ := json.Marshal(data)
	response, err := postJsonTimeout(this.url, string(jsonData))
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			response, err = this.onlinePINReversal()
			if err != nil {
				return "", err
			}
		}
	}
	result, err := this.verify(response)
	if err != nil {
		return "", err
	}
	return result, nil
}

func (this *Client) onlinePINReversal() (string, error) {
	this.setMsgType("Reversal")
	this.setTxnType("PIN")
	this.unsetAccountNo()
	this.setPosDateTime()
	sign, err := this.sign(this.getPayload())
	if err != nil {
		return "", err
	}
	data := map[string]interface{}{
		"security": Security,
		"version":  Version,
		"msg": map[string]interface{}{
			"MsgType":     this.msgType,
			"TxnType":     this.txnType,
			"Amount":      fmt.Sprintf("%.2f", this.Amount),
			"MerchantID":  this.MerchantID,
			"OperatorID":  this.OperatorID,
			"RetTxnRef":   this.retTxnRef,
			"TerminalID":  this.TerminalID,
			"ProductCode": this.ProductCode,
			"POSDateTime": this.posDateTime,
			"TxnTraceID":  this.TxnTraceID,
		},
		"signature": map[string]string{
			"type":      "JWT",
			"value":     sign,
			"parameter": "{\"typ\":\"JWT\",\"alg\":\"RS256\"}",
		},
	}
	jsonData, _ := json.Marshal(data)
	response, err := postJson(this.url, string(jsonData))
	if err != nil {
		return "", err
	}
	result, err := this.verify(response)
	if err != nil {
		return "", err
	}

	return result, nil
}

func (this *Client) OnlinePINVoid(orgTxnRef string) (string, error) {
	this.setMsgType("Void")
	this.setTxnType("PIN")
	this.unsetAccountNo()
	this.setRetTxnRef()
	this.setPosDateTime()
	sign, err := this.sign(this.getPayload())
	if err != nil {
		return "", err
	}
	data := map[string]interface{}{
		"security": Security,
		"version":  Version,
		"msg": map[string]interface{}{
			"MsgType":     this.msgType,
			"TxnType":     this.txnType,
			"Amount":      fmt.Sprintf("%.2f", this.Amount),
			"MerchantID":  this.MerchantID,
			"OperatorID":  this.OperatorID,
			"OrgTxnRef":   orgTxnRef,
			"RetTxnRef":   this.retTxnRef,
			"TerminalID":  this.TerminalID,
			"ProductCode": this.ProductCode,
			"POSDateTime": this.posDateTime,
			"TxnTraceID":  this.TxnTraceID,
		},
		"signature": map[string]string{
			"type":      "JWT",
			"value":     sign,
			"parameter": "{\"typ\":\"JWT\",\"alg\":\"RS256\"}",
		},
	}
	jsonData, _ := json.Marshal(data)
	response, err := postJson(this.url, string(jsonData))
	if err != nil {
		return "", err
	}
	result, err := this.verify(response)
	if err != nil {
		return "", err
	}

	return result, nil
}

func (this *Client) Etopup() (string, error) {
	this.setMsgType("Sale")
	this.setTxnType("ETU")
	this.setRetTxnRef()
	this.setPosDateTime()
	sign, err := this.sign(this.getPayload())
	if err != nil {
		return "", err
	}
	data := map[string]interface{}{
		"security": Security,
		"version":  Version,
		"msg": map[string]interface{}{
			"MsgType":     this.msgType,
			"TxnType":     this.txnType,
			"Amount":      fmt.Sprintf("%.2f", this.Amount),
			"MerchantID":  this.MerchantID,
			"OperatorID":  this.OperatorID,
			"RetTxnRef":   this.retTxnRef,
			"TerminalID":  this.TerminalID,
			"ProductCode": this.ProductCode,
			"AccountNo":   this.AccountNo,
			"POSDateTime": this.posDateTime,
			"TxnTraceID":  this.TxnTraceID,
		},
		"signature": map[string]string{
			"type":      "JWT",
			"value":     sign,
			"parameter": "{\"typ\":\"JWT\",\"alg\":\"RS256\"}",
		},
	}
	jsonData, _ := json.Marshal(data)
	response, err := postJson(this.url, string(jsonData))
	// timeout processing
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			response, err = this.etopupReversal()
			if err != nil {
				return "", err
			}
		}
	}
	result, err := this.verify(response)
	if err != nil {
		return "", err
	}
	return result, nil
}

func (this *Client) etopupReversal() (string, error) {
	this.setMsgType("Reversal")
	this.setTxnType("ETU")
	this.setPosDateTime()
	sign, err := this.sign(this.getPayload())
	if err != nil {
		return "", err
	}
	data := map[string]interface{}{
		"security": Security,
		"version":  Version,
		"msg": map[string]interface{}{
			"MsgType":     this.msgType,
			"TxnType":     this.txnType,
			"Amount":      fmt.Sprintf("%.2f", this.Amount),
			"MerchantID":  this.MerchantID,
			"OperatorID":  this.OperatorID,
			"RetTxnRef":   this.retTxnRef,
			"TerminalID":  this.TerminalID,
			"ProductCode": this.ProductCode,
			"AccountNo":   this.AccountNo,
			"POSDateTime": this.posDateTime,
			"TxnTraceID":  this.TxnTraceID,
		},
		"signature": map[string]string{
			"type":      "JWT",
			"value":     sign,
			"parameter": "{\"typ\":\"JWT\",\"alg\":\"RS256\"}",
		},
	}
	jsonData, _ := json.Marshal(data)
	response, err := postJson(this.url, string(jsonData))
	if err != nil {
		return "", err
	}
	result, err := this.verify(response)
	if err != nil {
		return "", err
	}

	return result, nil
}

func (this *Client) EtopupVoid(orgTxnRef string) (string, error) {
	this.setMsgType("Void")
	this.setTxnType("ETU")
	this.setRetTxnRef()
	this.setPosDateTime()
	this.unsetAccountNo()
	sign, err := this.sign(this.getPayload())
	if err != nil {
		return "", err
	}
	data := map[string]interface{}{
		"security": Security,
		"version":  Version,
		"msg": map[string]interface{}{
			"MsgType":     this.msgType,
			"TxnType":     this.txnType,
			"Amount":      fmt.Sprintf("%.2f", this.Amount),
			"MerchantID":  this.MerchantID,
			"OperatorID":  this.OperatorID,
			"OrgTxnRef":   orgTxnRef,
			"RetTxnRef":   this.retTxnRef,
			"TerminalID":  this.TerminalID,
			"ProductCode": this.ProductCode,
			"POSDateTime": this.posDateTime,
			"TxnTraceID":  this.TxnTraceID,
		},
		"signature": map[string]string{
			"type":      "JWT",
			"value":     sign,
			"parameter": "{\"typ\":\"JWT\",\"alg\":\"RS256\"}",
		},
	}
	jsonData, _ := json.Marshal(data)
	response, err := postJson(this.url, string(jsonData))
	if err != nil {
		return "", err
	}
	result, err := this.verify(response)
	if err != nil {
		return "", err
	}

	return result, nil
}

func (this *Client) EtopupTxnUpload(uploadData string) (string, error) {
	this.setMsgType("TxnUpload")
	this.setTxnType("ETU")
	this.setRetTxnRef()
	this.setPosDateTime()
	this.unsetAccountNo()
	sign, err := this.sign(this.getPayload())
	if err != nil {
		return "", err
	}
	data := map[string]interface{}{
		"security": Security,
		"version":  Version,
		"msg": map[string]interface{}{
			"MsgType":      this.msgType,
			"TxnType":      this.txnType,
			"Amount":       fmt.Sprintf("%.2f", this.Amount),
			"MerchantID":   this.MerchantID,
			"OperatorID":   this.OperatorID,
			"RetTxnRef":    this.retTxnRef,
			"TerminalID":   this.TerminalID,
			"ProductCode":  this.ProductCode,
			"POSDateTime":  this.posDateTime,
			"TxnTraceID":   this.TxnTraceID,
			"CustomField5": uploadData,
		},
		"signature": map[string]string{
			"type":      "JWT",
			"value":     sign,
			"parameter": "{\"typ\":\"JWT\",\"alg\":\"RS256\"}",
		},
	}
	jsonData, _ := json.Marshal(data)
	response, err := postJson(this.url, string(jsonData))
	if err != nil {
		return "", err
	}
	result, err := this.verify(response)
	if err != nil {
		return "", err
	}

	return result, nil
}

func (this *Client) Payment() (string, error) {
	this.setMsgType("Sale")
	this.setTxnType("PMT")
	this.setRetTxnRef()
	this.setPosDateTime()
	sign, err := this.sign(this.getPayload())
	if err != nil {
		return "", err
	}
	data := map[string]interface{}{
		"security": Security,
		"version":  Version,
		"msg": map[string]interface{}{
			"MsgType":     this.msgType,
			"TxnType":     this.txnType,
			"Amount":      fmt.Sprintf("%.2f", this.Amount),
			"MerchantID":  this.MerchantID,
			"OperatorID":  this.OperatorID,
			"RetTxnRef":   this.retTxnRef,
			"TerminalID":  this.TerminalID,
			"ProductCode": this.ProductCode,
			"AccountNo":   this.AccountNo,
			"POSDateTime": this.posDateTime,
			"TxnTraceID":  this.TxnTraceID,
		},
		"signature": map[string]string{
			"type":      "JWT",
			"value":     sign,
			"parameter": "{\"typ\":\"JWT\",\"alg\":\"RS256\"}",
		},
	}
	jsonData, _ := json.Marshal(data)
	response, err := postJson(this.url, string(jsonData))
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			response, err = this.paymentReversal()
			if err != nil {
				return "", err
			}
		}
	}
	result, err := this.verify(response)
	if err != nil {
		return "", err
	}
	return result, nil
}

func (this *Client) paymentReversal() (string, error) {
	this.setMsgType("Reversal")
	this.setTxnType("PMT")
	this.setPosDateTime()
	sign, err := this.sign(this.getPayload())
	if err != nil {
		return "", err
	}
	data := map[string]interface{}{
		"security": Security,
		"version":  Version,
		"msg": map[string]interface{}{
			"MsgType":     this.msgType,
			"TxnType":     this.txnType,
			"Amount":      fmt.Sprintf("%.2f", this.Amount),
			"MerchantID":  this.MerchantID,
			"OperatorID":  this.OperatorID,
			"RetTxnRef":   this.retTxnRef,
			"TerminalID":  this.TerminalID,
			"ProductCode": this.ProductCode,
			"AccountNo":   this.AccountNo,
			"POSDateTime": this.posDateTime,
			"TxnTraceID":  this.TxnTraceID,
		},
		"signature": map[string]string{
			"type":      "JWT",
			"value":     sign,
			"parameter": "{\"typ\":\"JWT\",\"alg\":\"RS256\"}",
		},
	}
	jsonData, _ := json.Marshal(data)
	response, err := postJson(this.url, string(jsonData))
	if err != nil {
		return "", err
	}
	result, err := this.verify(response)
	if err != nil {
		return "", err
	}

	return result, nil
}

func (this *Client) PaymentVoid(orgTxnRef string) (string, error) {
	this.setMsgType("Void")
	this.setTxnType("PMT")
	this.setRetTxnRef()
	this.setPosDateTime()
	this.unsetAccountNo()
	sign, err := this.sign(this.getPayload())
	if err != nil {
		return "", err
	}
	data := map[string]interface{}{
		"security": Security,
		"version":  Version,
		"msg": map[string]interface{}{
			"MsgType":     this.msgType,
			"TxnType":     this.txnType,
			"Amount":      fmt.Sprintf("%.2f", this.Amount),
			"MerchantID":  this.MerchantID,
			"OperatorID":  this.OperatorID,
			"OrgTxnRef":   orgTxnRef,
			"RetTxnRef":   this.retTxnRef,
			"TerminalID":  this.TerminalID,
			"ProductCode": this.ProductCode,
			"POSDateTime": this.posDateTime,
			"TxnTraceID":  this.TxnTraceID,
		},
		"signature": map[string]string{
			"type":      "JWT",
			"value":     sign,
			"parameter": "{\"typ\":\"JWT\",\"alg\":\"RS256\"}",
		},
	}
	jsonData, _ := json.Marshal(data)
	response, err := postJson(this.url, string(jsonData))
	if err != nil {
		return "", err
	}
	result, err := this.verify(response)
	if err != nil {
		return "", err
	}

	return result, nil
}

func (this *Client) PaymentRefund(orgTxnRef string) (string, error) {
	this.setMsgType("Refund")
	this.setTxnType("PMT")
	this.setRetTxnRef()
	this.setPosDateTime()
	this.unsetAccountNo()
	sign, err := this.sign(this.getPayload())
	if err != nil {
		return "", err
	}
	data := map[string]interface{}{
		"security": Security,
		"version":  Version,
		"msg": map[string]interface{}{
			"MsgType":     this.msgType,
			"TxnType":     this.txnType,
			"Amount":      fmt.Sprintf("%.2f", this.Amount),
			"MerchantID":  this.MerchantID,
			"OperatorID":  this.OperatorID,
			"OrgTxnRef":   orgTxnRef,
			"RetTxnRef":   this.retTxnRef,
			"TerminalID":  this.TerminalID,
			"ProductCode": this.ProductCode,
			"POSDateTime": this.posDateTime,
			"TxnTraceID":  this.TxnTraceID,
		},
		"signature": map[string]string{
			"type":      "JWT",
			"value":     sign,
			"parameter": "{\"typ\":\"JWT\",\"alg\":\"RS256\"}",
		},
	}
	jsonData, _ := json.Marshal(data)
	response, err := postJson(this.url, string(jsonData))
	if err != nil {
		return "", err
	}
	result, err := this.verify(response)
	if err != nil {
		return "", err
	}

	return result, nil
}

func (this *Client) PaymentSeamless() (string, error) {
	this.setMsgType("Sale")
	this.setTxnType("PMT")
	this.setRetTxnRef()
	this.setPosDateTime()
	this.unsetProductCode()
	sign, err := this.sign(this.getPayload())
	if err != nil {
		return "", err
	}
	data := map[string]interface{}{
		"security": Security,
		"version":  Version,
		"msg": map[string]interface{}{
			"MsgType":     this.msgType,
			"TxnType":     this.txnType,
			"Amount":      fmt.Sprintf("%.2f", this.Amount),
			"MerchantID":  this.MerchantID,
			"OperatorID":  this.OperatorID,
			"RetTxnRef":   this.retTxnRef,
			"TerminalID":  this.TerminalID,
			"AccountNo":   this.AccountNo,
			"POSDateTime": this.posDateTime,
			"TxnTraceID":  this.TxnTraceID,
		},
		"signature": map[string]string{
			"type":      "JWT",
			"value":     sign,
			"parameter": "{\"typ\":\"JWT\",\"alg\":\"RS256\"}",
		},
	}
	jsonData, _ := json.Marshal(data)
	response, err := postJson(this.url, string(jsonData))
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			response, err = this.paymentSeamlessReversal()
			if err != nil {
				return "", err
			}
		}
	}
	result, err := this.verify(response)
	if err != nil {
		return "", err
	}
	return result, nil
}

func (this *Client) paymentSeamlessReversal() (string, error) {
	this.setMsgType("Reversal")
	this.setTxnType("PMT")
	this.setPosDateTime()
	sign, err := this.sign(this.getPayload())
	if err != nil {
		return "", err
	}
	data := map[string]interface{}{
		"security": Security,
		"version":  Version,
		"msg": map[string]interface{}{
			"MsgType":     this.msgType,
			"TxnType":     this.txnType,
			"Amount":      fmt.Sprintf("%.2f", this.Amount),
			"MerchantID":  this.MerchantID,
			"OperatorID":  this.OperatorID,
			"RetTxnRef":   this.retTxnRef,
			"TerminalID":  this.TerminalID,
			"AccountNo":   this.AccountNo,
			"POSDateTime": this.posDateTime,
			"TxnTraceID":  this.TxnTraceID,
		},
		"signature": map[string]string{
			"type":      "JWT",
			"value":     sign,
			"parameter": "{\"typ\":\"JWT\",\"alg\":\"RS256\"}",
		},
	}
	jsonData, _ := json.Marshal(data)
	response, err := postJson(this.url, string(jsonData))
	if err != nil {
		return "", err
	}
	result, err := this.verify(response)
	if err != nil {
		return "", err
	}

	return result, nil
}

func (this *Client) PaymentSeamlessVoid(orgTxnRef string) (string, error) {
	this.setMsgType("Void")
	this.setTxnType("PMT")
	this.setRetTxnRef()
	this.setPosDateTime()
	sign, err := this.sign(this.getPayload())
	if err != nil {
		return "", err
	}
	data := map[string]interface{}{
		"security": Security,
		"version":  Version,
		"msg": map[string]interface{}{
			"MsgType":     this.msgType,
			"TxnType":     this.txnType,
			"Amount":      fmt.Sprintf("%.2f", this.Amount),
			"MerchantID":  this.MerchantID,
			"OperatorID":  this.OperatorID,
			"OrgTxnRef":   orgTxnRef,
			"RetTxnRef":   this.retTxnRef,
			"TerminalID":  this.TerminalID,
			"AccountNo":   this.AccountNo,
			"POSDateTime": this.posDateTime,
			"TxnTraceID":  this.TxnTraceID,
		},
		"signature": map[string]string{
			"type":      "JWT",
			"value":     sign,
			"parameter": "{\"typ\":\"JWT\",\"alg\":\"RS256\"}",
		},
	}
	jsonData, _ := json.Marshal(data)
	response, err := postJson(this.url, string(jsonData))
	if err != nil {
		return "", err
	}
	result, err := this.verify(response)
	if err != nil {
		return "", err
	}

	return result, nil
}

func (this *Client) PaymentSeamlessRefund(orgTxnRef string) (string, error) {
	this.setMsgType("Refund")
	this.setTxnType("PMT")
	this.setRetTxnRef()
	this.setPosDateTime()
	sign, err := this.sign(this.getPayload())
	if err != nil {
		return "", err
	}
	data := map[string]interface{}{
		"security": Security,
		"version":  Version,
		"msg": map[string]interface{}{
			"MsgType":     this.msgType,
			"TxnType":     this.txnType,
			"Amount":      fmt.Sprintf("%.2f", this.Amount),
			"MerchantID":  this.MerchantID,
			"OperatorID":  this.OperatorID,
			"OrgTxnRef":   orgTxnRef,
			"RetTxnRef":   this.retTxnRef,
			"TerminalID":  this.TerminalID,
			"AccountNo":   this.AccountNo,
			"POSDateTime": this.posDateTime,
			"TxnTraceID":  this.TxnTraceID,
		},
		"signature": map[string]string{
			"type":      "JWT",
			"value":     sign,
			"parameter": "{\"typ\":\"JWT\",\"alg\":\"RS256\"}",
		},
	}
	jsonData, _ := json.Marshal(data)
	response, err := postJson(this.url, string(jsonData))
	if err != nil {
		return "", err
	}
	result, err := this.verify(response)
	if err != nil {
		return "", err
	}

	return result, nil
}

func (this *Client) PaymentAsynchronous() (string, error) {
	this.setMsgType("Sale")
	this.setTxnType("PMT")
	this.setRetTxnRef()
	this.setPosDateTime()
	sign, err := this.sign(this.getPayload())
	if err != nil {
		return "", err
	}
	data := map[string]interface{}{
		"security": Security,
		"version":  Version,
		"msg": map[string]interface{}{
			"MsgType":     this.msgType,
			"TxnType":     this.txnType,
			"Amount":      fmt.Sprintf("%.2f", this.Amount),
			"MerchantID":  this.MerchantID,
			"OperatorID":  this.OperatorID,
			"RetTxnRef":   this.retTxnRef,
			"TerminalID":  this.TerminalID,
			"ProductCode": this.ProductCode,
			"AccountNo":   this.AccountNo,
			"POSDateTime": this.posDateTime,
			"TxnTraceID":  this.TxnTraceID,
		},
		"signature": map[string]string{
			"type":      "JWT",
			"value":     sign,
			"parameter": "{\"typ\":\"JWT\",\"alg\":\"RS256\"}",
		},
	}
	jsonData, _ := json.Marshal(data)
	response, err := postJson(this.url, string(jsonData))
	if err != nil {
		return "", err
	}
	result, err := this.verify(response)
	if err != nil {
		return "", err
	}
	return result, nil
}

func (this *Client) PaymentQuery(orgTxnRef string) (string, error) {
	this.setMsgType("Query")
	this.setTxnType("PMT")
	this.setRetTxnRef()
	this.setPosDateTime()
	this.unsetAccountNo()
	sign, err := this.sign(this.getPayload())
	if err != nil {
		return "", err
	}
	data := map[string]interface{}{
		"security": Security,
		"version":  Version,
		"msg": map[string]interface{}{
			"MsgType":     this.msgType,
			"TxnType":     this.txnType,
			"Amount":      fmt.Sprintf("%.2f", this.Amount),
			"MerchantID":  this.MerchantID,
			"OperatorID":  this.OperatorID,
			"RetTxnRef":   this.retTxnRef,
			"OrgTxnRef":   orgTxnRef,
			"TerminalID":  this.TerminalID,
			"ProductCode": this.ProductCode,
			"POSDateTime": this.posDateTime,
			"TxnTraceID":  this.TxnTraceID,
		},
		"signature": map[string]string{
			"type":      "JWT",
			"value":     sign,
			"parameter": "{\"typ\":\"JWT\",\"alg\":\"RS256\"}",
		},
	}
	jsonData, _ := json.Marshal(data)
	response, err := postJson(this.url, string(jsonData))
	if err != nil {
		return "", err
	}
	result, err := this.verify(response)
	if err != nil {
		return "", err
	}

	return result, nil
}

func (this *Client) PaymentTxnUpload(uploadData string) (string, error) {
	this.setMsgType("TxnUpload")
	this.setTxnType("PMT")
	this.setRetTxnRef()
	this.setPosDateTime()
	this.unsetAccountNo()
	sign, err := this.sign(this.getPayload())
	if err != nil {
		return "", err
	}
	data := map[string]interface{}{
		"security": Security,
		"version":  Version,
		"msg": map[string]interface{}{
			"MsgType":      this.msgType,
			"TxnType":      this.txnType,
			"Amount":       fmt.Sprintf("%.2f", this.Amount),
			"MerchantID":   this.MerchantID,
			"OperatorID":   this.OperatorID,
			"RetTxnRef":    this.retTxnRef,
			"TerminalID":   this.TerminalID,
			"ProductCode":  this.ProductCode,
			"POSDateTime":  this.posDateTime,
			"TxnTraceID":   this.TxnTraceID,
			"CustomField5": uploadData,
		},
		"signature": map[string]string{
			"type":      "JWT",
			"value":     sign,
			"parameter": "{\"typ\":\"JWT\",\"alg\":\"RS256\"}",
		},
	}
	jsonData, _ := json.Marshal(data)
	response, err := postJson(this.url, string(jsonData))
	if err != nil {
		return "", err
	}
	result, err := this.verify(response)
	if err != nil {
		return "", err
	}

	return result, nil
}
