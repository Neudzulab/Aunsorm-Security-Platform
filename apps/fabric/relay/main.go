package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type RelayConfig struct {
	PeerEndpoint string
	TLSCertPath  string
	MSPID        string
	CertPath     string
	KeyPath      string
	Channel      string
	Chaincode    string
	SinkURL      string
}

type AuditEvent struct {
	Name        string `json:"name"`
	TxID        string `json:"txId"`
	BlockNumber uint64 `json:"blockNumber"`
	PayloadB64  string `json:"payloadB64"`
	ReceivedAt  string `json:"receivedAt"`
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		panic(err)
	}
	relay(cfg)
}

func relay(cfg RelayConfig) {
	tlsCreds, err := credentials.NewClientTLSFromFile(cfg.TLSCertPath, "")
	if err != nil {
		panic(err)
	}
	conn, err := grpc.Dial(cfg.PeerEndpoint, grpc.WithTransportCredentials(tlsCreds))
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	id, sign := loadIdentity(cfg.MSPID, cfg.CertPath, cfg.KeyPath)

	gw, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithClientConnection(conn),
		client.WithEvaluateTimeout(10*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(20*time.Second),
		client.WithCommitStatusTimeout(60*time.Second),
	)
	if err != nil {
		panic(err)
	}
	defer gw.Close()

	network := gw.GetNetwork(cfg.Channel)
	contract := network.GetContract(cfg.Chaincode)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events, err := contract.ChaincodeEvents(ctx)
	if err != nil {
		panic(err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	for event := range events {
		payload := AuditEvent{
			Name:        event.EventName,
			TxID:        event.TransactionID,
			BlockNumber: event.BlockNumber,
			PayloadB64:  base64.StdEncoding.EncodeToString(event.Payload),
			ReceivedAt:  time.Now().UTC().Format(time.RFC3339Nano),
		}
		if err := postEvent(client, cfg.SinkURL, payload); err != nil {
			fmt.Fprintf(os.Stderr, "event relay failed: %v\n", err)
		}
	}
}

func loadConfig() (RelayConfig, error) {
	cfg := RelayConfig{
		PeerEndpoint: os.Getenv("AUNSORM_FABRIC_GW_PEER_ENDPOINT"),
		TLSCertPath:  os.Getenv("AUNSORM_FABRIC_GW_TLS_CERT"),
		MSPID:        os.Getenv("AUNSORM_FABRIC_GW_MSP_ID"),
		CertPath:     os.Getenv("AUNSORM_FABRIC_GW_CERT"),
		KeyPath:      os.Getenv("AUNSORM_FABRIC_GW_KEY"),
		Channel:      os.Getenv("AUNSORM_FABRIC_CHANNEL"),
		Chaincode:    os.Getenv("AUNSORM_FABRIC_CHAINCODE"),
		SinkURL:      os.Getenv("AUNSORM_AUDIT_SINK_URL"),
	}
	missing := []string{}
	if cfg.PeerEndpoint == "" {
		missing = append(missing, "AUNSORM_FABRIC_GW_PEER_ENDPOINT")
	}
	if cfg.TLSCertPath == "" {
		missing = append(missing, "AUNSORM_FABRIC_GW_TLS_CERT")
	}
	if cfg.MSPID == "" {
		missing = append(missing, "AUNSORM_FABRIC_GW_MSP_ID")
	}
	if cfg.CertPath == "" {
		missing = append(missing, "AUNSORM_FABRIC_GW_CERT")
	}
	if cfg.KeyPath == "" {
		missing = append(missing, "AUNSORM_FABRIC_GW_KEY")
	}
	if cfg.Channel == "" {
		missing = append(missing, "AUNSORM_FABRIC_CHANNEL")
	}
	if cfg.Chaincode == "" {
		missing = append(missing, "AUNSORM_FABRIC_CHAINCODE")
	}
	if cfg.SinkURL == "" {
		missing = append(missing, "AUNSORM_AUDIT_SINK_URL")
	}
	if len(missing) > 0 {
		return RelayConfig{}, fmt.Errorf("missing env: %s", strings.Join(missing, ", "))
	}
	return cfg, nil
}

func loadIdentity(mspID, certPath, keyPath string) (*identity.X509Identity, identity.Sign) {
	cert, err := loadX509Certificate(certPath)
	if err != nil {
		panic(err)
	}
	id, err := identity.NewX509Identity(mspID, cert)
	if err != nil {
		panic(err)
	}
	key, err := loadPrivateKey(keyPath)
	if err != nil {
		panic(err)
	}
	sign, err := identity.NewPrivateKeySign(key)
	if err != nil {
		panic(err)
	}
	return id, sign
}

func loadX509Certificate(path string) (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return identity.CertificateFromPEM(certPEM)
}

func loadPrivateKey(path string) (any, error) {
	keyPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return identity.PrivateKeyFromPEM(keyPEM)
}

func postEvent(client *http.Client, sinkURL string, event AuditEvent) error {
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, sinkURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		payload, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("sink response %d: %s", resp.StatusCode, string(payload))
	}
	return nil
}
