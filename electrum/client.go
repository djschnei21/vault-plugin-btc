package electrum

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Client represents an Electrum protocol client
type Client struct {
	conn     net.Conn
	mu       sync.Mutex
	id       atomic.Uint64
	url      string
	useTLS   bool
	host     string
	port     string
	respChan map[uint64]chan *rpcResponse
	respMu   sync.Mutex
	closed   bool
}

type rpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      uint64        `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Balance represents the balance response from Electrum
type Balance struct {
	Confirmed   int64 `json:"confirmed"`
	Unconfirmed int64 `json:"unconfirmed"`
}

// UTXO represents an unspent transaction output
type UTXO struct {
	TxHash string `json:"tx_hash"`
	TxPos  int    `json:"tx_pos"`
	Height int64  `json:"height"`
	Value  int64  `json:"value"`
}

// Transaction represents transaction history item
type Transaction struct {
	TxHash string `json:"tx_hash"`
	Height int64  `json:"height"`
	Fee    int64  `json:"fee,omitempty"`
}

// NewClient creates a new Electrum client
func NewClient(url string) (*Client, error) {
	c := &Client{
		url:      url,
		respChan: make(map[uint64]chan *rpcResponse),
	}

	if err := c.parseURL(url); err != nil {
		return nil, err
	}

	if err := c.connect(); err != nil {
		return nil, err
	}

	// Start response reader
	go c.readResponses()

	// Negotiate protocol version
	if err := c.negotiateVersion(); err != nil {
		c.Close()
		return nil, err
	}

	return c, nil
}

func (c *Client) parseURL(url string) error {
	if strings.HasPrefix(url, "ssl://") {
		c.useTLS = true
		url = strings.TrimPrefix(url, "ssl://")
	} else if strings.HasPrefix(url, "tcp://") {
		c.useTLS = false
		url = strings.TrimPrefix(url, "tcp://")
	} else {
		// Default to TLS
		c.useTLS = true
	}

	parts := strings.Split(url, ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid URL format: expected host:port")
	}

	c.host = parts[0]
	c.port = parts[1]

	return nil
}

func (c *Client) connect() error {
	addr := net.JoinHostPort(c.host, c.port)

	var conn net.Conn
	var err error

	if c.useTLS {
		conn, err = tls.DialWithDialer(&net.Dialer{
			Timeout: 30 * time.Second,
		}, "tcp", addr, &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: c.host, // Explicit ServerName for proper certificate validation
		})
	} else {
		conn, err = net.DialTimeout("tcp", addr, 30*time.Second)
	}

	if err != nil {
		return fmt.Errorf("failed to connect to Electrum server: %w", err)
	}

	c.conn = conn
	return nil
}

func (c *Client) readResponses() {
	decoder := json.NewDecoder(c.conn)
	for {
		var resp rpcResponse
		if err := decoder.Decode(&resp); err != nil {
			c.mu.Lock()
			closed := c.closed
			c.mu.Unlock()
			if !closed {
				// Connection error, close all waiting channels
				c.respMu.Lock()
				for _, ch := range c.respChan {
					close(ch)
				}
				c.respChan = make(map[uint64]chan *rpcResponse)
				c.respMu.Unlock()
			}
			return
		}

		c.respMu.Lock()
		if ch, ok := c.respChan[resp.ID]; ok {
			ch <- &resp
			delete(c.respChan, resp.ID)
		}
		c.respMu.Unlock()
	}
}

func (c *Client) call(method string, params ...interface{}) (json.RawMessage, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, fmt.Errorf("client is closed")
	}
	c.mu.Unlock()

	id := c.id.Add(1)

	req := rpcRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  params,
	}

	respCh := make(chan *rpcResponse, 1)
	c.respMu.Lock()
	c.respChan[id] = respCh
	c.respMu.Unlock()

	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')

	c.mu.Lock()
	_, err = c.conn.Write(data)
	c.mu.Unlock()
	if err != nil {
		c.respMu.Lock()
		delete(c.respChan, id)
		c.respMu.Unlock()
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Wait for response with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	select {
	case resp, ok := <-respCh:
		if !ok {
			return nil, fmt.Errorf("connection closed")
		}
		if resp.Error != nil {
			return nil, fmt.Errorf("electrum error %d: %s", resp.Error.Code, resp.Error.Message)
		}
		return resp.Result, nil
	case <-ctx.Done():
		c.respMu.Lock()
		delete(c.respChan, id)
		c.respMu.Unlock()
		return nil, fmt.Errorf("request timeout")
	}
}

func (c *Client) negotiateVersion() error {
	result, err := c.call("server.version", "vault-plugin-btc", "1.4")
	if err != nil {
		return fmt.Errorf("version negotiation failed: %w", err)
	}

	var version []string
	if err := json.Unmarshal(result, &version); err != nil {
		return fmt.Errorf("failed to parse version response: %w", err)
	}

	return nil
}

// Close closes the client connection
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		if c.conn != nil {
			c.conn.Close()
		}
	}
}

// GetBalance returns the balance for a scripthash
func (c *Client) GetBalance(scripthash string) (*Balance, error) {
	result, err := c.call("blockchain.scripthash.get_balance", scripthash)
	if err != nil {
		return nil, err
	}

	var balance Balance
	if err := json.Unmarshal(result, &balance); err != nil {
		return nil, fmt.Errorf("failed to parse balance: %w", err)
	}

	return &balance, nil
}

// ListUnspent returns unspent outputs for a scripthash
func (c *Client) ListUnspent(scripthash string) ([]UTXO, error) {
	result, err := c.call("blockchain.scripthash.listunspent", scripthash)
	if err != nil {
		return nil, err
	}

	var utxos []UTXO
	if err := json.Unmarshal(result, &utxos); err != nil {
		return nil, fmt.Errorf("failed to parse UTXOs: %w", err)
	}

	return utxos, nil
}

// GetHistory returns transaction history for a scripthash
func (c *Client) GetHistory(scripthash string) ([]Transaction, error) {
	result, err := c.call("blockchain.scripthash.get_history", scripthash)
	if err != nil {
		return nil, err
	}

	var txs []Transaction
	if err := json.Unmarshal(result, &txs); err != nil {
		return nil, fmt.Errorf("failed to parse history: %w", err)
	}

	return txs, nil
}

// GetTransaction returns raw transaction data
func (c *Client) GetTransaction(txhash string) (string, error) {
	result, err := c.call("blockchain.transaction.get", txhash)
	if err != nil {
		return "", err
	}

	var rawtx string
	if err := json.Unmarshal(result, &rawtx); err != nil {
		return "", fmt.Errorf("failed to parse transaction: %w", err)
	}

	return rawtx, nil
}

// BroadcastTransaction broadcasts a raw transaction and returns the txid
func (c *Client) BroadcastTransaction(rawtx string) (string, error) {
	result, err := c.call("blockchain.transaction.broadcast", rawtx)
	if err != nil {
		return "", err
	}

	var txid string
	if err := json.Unmarshal(result, &txid); err != nil {
		return "", fmt.Errorf("failed to parse broadcast result: %w", err)
	}

	return txid, nil
}

// EstimateFee returns the estimated fee in BTC per kilobyte
func (c *Client) EstimateFee(blocks int) (float64, error) {
	result, err := c.call("blockchain.estimatefee", blocks)
	if err != nil {
		return 0, err
	}

	var fee float64
	if err := json.Unmarshal(result, &fee); err != nil {
		return 0, fmt.Errorf("failed to parse fee estimate: %w", err)
	}

	return fee, nil
}

// GetBlockHeader returns the block header at the given height
func (c *Client) GetBlockHeader(height int64) (string, error) {
	result, err := c.call("blockchain.block.header", height)
	if err != nil {
		return "", err
	}

	var header string
	if err := json.Unmarshal(result, &header); err != nil {
		return "", fmt.Errorf("failed to parse block header: %w", err)
	}

	return header, nil
}

// Ping sends a ping to keep the connection alive
func (c *Client) Ping() error {
	_, err := c.call("server.ping")
	return err
}

// Subscribe subscribes to a scripthash and returns its current status hash.
// The status hash is a hash of the address's transaction history - it changes
// whenever any transaction involving this address is added or confirmed.
// Returns nil if the address has no transaction history.
func (c *Client) Subscribe(scripthash string) (*string, error) {
	result, err := c.call("blockchain.scripthash.subscribe", scripthash)
	if err != nil {
		return nil, err
	}

	// Status can be null if no transactions
	if string(result) == "null" {
		return nil, nil
	}

	var status string
	if err := json.Unmarshal(result, &status); err != nil {
		return nil, fmt.Errorf("failed to parse subscribe result: %w", err)
	}

	return &status, nil
}

// GetBlockHeight returns the current block height from server
func (c *Client) GetBlockHeight() (int64, error) {
	// Subscribe to headers to get current height
	result, err := c.call("blockchain.headers.subscribe")
	if err != nil {
		return 0, err
	}

	var headerInfo struct {
		Height int64  `json:"height"`
		Hex    string `json:"hex"`
	}
	if err := json.Unmarshal(result, &headerInfo); err != nil {
		return 0, fmt.Errorf("failed to parse header info: %w", err)
	}

	return headerInfo.Height, nil
}

// AddressToScriptHash converts a Bitcoin address to an Electrum scripthash
// The scripthash is SHA256 of the scriptPubKey, reversed (little-endian)
func AddressToScriptHash(scriptPubKey []byte) string {
	hash := sha256.Sum256(scriptPubKey)
	// Reverse for little-endian
	for i, j := 0, len(hash)-1; i < j; i, j = i+1, j-1 {
		hash[i], hash[j] = hash[j], hash[i]
	}
	return hex.EncodeToString(hash[:])
}
