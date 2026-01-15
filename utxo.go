package btc

// UTXOInfo represents detailed UTXO information
type UTXOInfo struct {
	TxID          string `json:"txid"`
	Vout          int    `json:"vout"`
	Value         int64  `json:"value"`
	Address       string `json:"address"`
	AddressIndex  uint32 `json:"address_index"`
	ScriptHash    string `json:"scripthash"`
	Height        int64  `json:"height"`
	Confirmations int64  `json:"confirmations"`
}
