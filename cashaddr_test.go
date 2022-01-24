package ecashutil

import (
	"github.com/martinboehm/btcutil"
	"github.com/martinboehm/btcutil/chaincfg"
	"testing"
)

var TestVectorsP2PKH = [][]string{
	{"1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu", "ecash:qpm2qsznhks23z7629mms6s4cwef74vcwva87rkuu2"},
	{"1KXrWXciRDZUpQwQmuM1DbwsKDLYAYsVLR", "ecash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4ykdcjcn6n"},
	{"16w1D5WRVKJuZUsSRzdLp9w3YGcgoxDXb", "ecash:qqq3728yw0y47sqn6l2na30mcw6zm78dzq653y7pv5"},
}

var TestVectorsP2SH = [][]string{
	{"3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC", "ecash:ppm2qsznhks23z7629mms6s4cwef74vcwv2zrv3l8h"},
	{"3LDsS579y7sruadqu11beEJoTjdFiFCdX4", "ecash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4ypg9alspw"},
	{"31nwvkZwyPdgzjBJZXfDmSWsC4ZLKpYyUw", "ecash:pqq3728yw0y47sqn6l2na30mcw6zm78dzqd3vtezhf"},
}

var valid []string = []string{
	"prefix:x64nx6hz",
	"PREFIX:X64NX6HZ",
	"p:gpf8m4h7",
	"bitcoincash:qpzry9x8gf2tvdw0s3jn54khce6mua7lcw20ayyn",
	"bchtest:testnetaddress4d6njnut",
	"bchreg:555555555555555555555555555555555555555555555udxmlmrz",
}

func TestValid(t *testing.T) {
	for _, s := range valid {
		_, _, err := DecodeCashAddress(s)
		if err != nil {
			t.Error(err)
		}
	}
}

var Invalid []string = []string{
	"prefix:x32nx6hz",
	"prEfix:x64nx6hz",
	"prefix:x64nx6Hz",
	"pref1x:6m8cxv73",
	"prefix:",
	":u9wsx07j",
	"bchreg:555555555555555555x55555555555555555555555555udxmlmrz",
	"bchreg:555555555555555555555555555555551555555555555udxmlmrz",
	"pre:fix:x32nx6hz",
	"prefixx64nx6hz",
}

func TestInvalid(t *testing.T) {
	for _, s := range Invalid {
		_, _, err := DecodeCashAddress(s)
		if err == nil {
			t.Error("Failed to error on invalid string")
		}
	}
}

func TestDecodeCashAddress(t *testing.T) {
	// Mainnet
	addr, err := DecodeAddress("ecash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4ykdcjcn6n", &chaincfg.MainNetParams)
	if err != nil {
		t.Error(err)
	}
	if addr.String() != "ecash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4ykdcjcn6n" {
		t.Error("Address decoding error")
	}
	addr1, err := DecodeAddress("ecash:ppm2qsznhks23z7629mms6s4cwef74vcwv2zrv3l8h", &chaincfg.MainNetParams)
	if err != nil {
		t.Error(err)
	}
	if addr1.String() != "ecash:ppm2qsznhks23z7629mms6s4cwef74vcwv2zrv3l8h" {
		t.Error("Address decoding error")
	}
	// Testnet
	addr, err = DecodeAddress("ecash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4ykdcjcn6n", &chaincfg.TestNet3Params)
	if err != nil {
		t.Error(err)
	}
	if addr.String() != "ecash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4ykdcjcn6n" {
		t.Error("Address decoding error")
	}
	// Regtest
	addr, err = DecodeAddress("ecreg:qr95sy3j9xwd2ap32xkykttr4cvcu7as4ytvd6xcl9", &chaincfg.RegressionNetParams)
	if err != nil {
		t.Error(err)
	}
	if addr.String() != "ecreg:qr95sy3j9xwd2ap32xkykttr4cvcu7as4ytvd6xcl9" {
		t.Error("Address decoding error")
	}
}

var dataElement = []byte{203, 72, 18, 50, 41, 156, 213, 116, 49, 81, 172, 75, 45, 99, 174, 25, 142, 123, 176, 169}

// Second address of https://github.com/Bitcoin-UAHF/spec/blob/master/cashaddr.md#examples-of-address-translation
func TestCashAddressPubKeyHash_EncodeAddress(t *testing.T) {
	// Mainnet
	addr, err := NewCashAddressPubKeyHash(dataElement, &chaincfg.MainNetParams)
	if err != nil {
		t.Error(err)
	}
	if addr.String() != "ecash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4ykdcjcn6n" {
		t.Error("Address decoding error")
	}
	// Testnet
	addr, err = NewCashAddressPubKeyHash(dataElement, &chaincfg.TestNet3Params)
	if err != nil {
		t.Error(err)
	}
	if addr.String() != "ectest:qr95sy3j9xwd2ap32xkykttr4cvcu7as4ysxxjl7ez" {
		t.Error("Address decoding error")
	}
	// Regtest
	addr, err = NewCashAddressPubKeyHash(dataElement, &chaincfg.RegressionNetParams)
	if err != nil {
		t.Error(err)
	}
	if addr.String() != "ecreg:qr95sy3j9xwd2ap32xkykttr4cvcu7as4ytvd6xcl9" {
		t.Error("Address decoding error")
	}
}

var dataElement2 = []byte{118, 160, 64, 83, 189, 160, 168, 139, 218, 81, 119, 184, 106, 21, 195, 178, 159, 85, 152, 115}

// 4th address of https://github.com/Bitcoin-UAHF/spec/blob/master/cashaddr.md#examples-of-address-translation
func TestCashAddressScriptHash_EncodeAddress(t *testing.T) {
	// Mainnet
	addr, err := NewCashAddressScriptHashFromHash(dataElement2, &chaincfg.MainNetParams)
	if err != nil {
		t.Error(err)
	}
	if addr.String() != "ecash:ppm2qsznhks23z7629mms6s4cwef74vcwv2zrv3l8h" {
		t.Error("Address decoding error")
	}
	// Testnet
	addr, err = NewCashAddressScriptHashFromHash(dataElement2, &chaincfg.TestNet3Params)
	if err != nil {
		t.Error(err)
	}
	if addr.String() != "ectest:ppm2qsznhks23z7629mms6s4cwef74vcwvvfavkjyx" {
		t.Error("Address decoding error")
	}
	// Regtest
	addr, err = NewCashAddressScriptHashFromHash(dataElement2, &chaincfg.RegressionNetParams)
	if err != nil {
		t.Error(err)
	}
	if addr.String() != "ecreg:ppm2qsznhks23z7629mms6s4cwef74vcwvhrky05zp" {
		t.Error("Address decoding error")
	}
}

func TestTestVectors(t *testing.T) {
	for _, v := range TestVectorsP2PKH {
		addr, err := btcutil.DecodeAddress(v[0], &chaincfg.MainNetParams)
		if err != nil {
			t.Error(err)
			return
		}
		addr2, err := NewCashAddressPubKeyHash(addr.ScriptAddress(), &chaincfg.MainNetParams)
		if err != nil {
			t.Error(err)
		}
		if addr2.String() != v[1] {
			t.Error("Failed to derive correct address")
		}
	}
	for _, v := range TestVectorsP2SH {
		addr, err := btcutil.DecodeAddress(v[0], &chaincfg.MainNetParams)
		if err != nil {
			t.Error(err)
			return
		}
		addr2, err := NewCashAddressScriptHashFromHash(addr.ScriptAddress(), &chaincfg.MainNetParams)
		if err != nil {
			t.Error(err)
		}
		if addr2.String() != v[1] {
			t.Error("Failed to derive correct address")
		}
	}
}
