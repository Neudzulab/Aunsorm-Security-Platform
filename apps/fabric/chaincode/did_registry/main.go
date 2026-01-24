package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type DidRegistryContract struct {
	contractapi.Contract
}

type DidRecord struct {
	Did                string `json:"did"`
	Controller         string `json:"controller"`
	Channel            string `json:"channel"`
	MspID              string `json:"mspId"`
	Status             string `json:"status"`
	VerificationMethod string `json:"verificationMethod"`
	ServiceEndpoint    string `json:"serviceEndpoint,omitempty"`
	LedgerAnchor       string `json:"ledgerAnchor"`
	UpdatedAtMs        uint64 `json:"updatedAtMs"`
}

func main() {
	chaincode, err := contractapi.NewChaincode(new(DidRegistryContract))
	if err != nil {
		panic(err)
	}
	if err := chaincode.Start(); err != nil {
		panic(err)
	}
}

func (c *DidRegistryContract) CreateDid(ctx contractapi.TransactionContextInterface, recordJSON string) error {
	if err := authorize(ctx); err != nil {
		return err
	}
	record, err := parseRecord(recordJSON)
	if err != nil {
		return err
	}
	exists, err := c.DidExists(ctx, record.Did)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("did already exists: %s", record.Did)
	}
	return writeRecord(ctx, record, "did.created")
}

func (c *DidRegistryContract) UpdateDid(ctx contractapi.TransactionContextInterface, recordJSON string) error {
	if err := authorize(ctx); err != nil {
		return err
	}
	record, err := parseRecord(recordJSON)
	if err != nil {
		return err
	}
	exists, err := c.DidExists(ctx, record.Did)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("did not found: %s", record.Did)
	}
	return writeRecord(ctx, record, "did.updated")
}

func (c *DidRegistryContract) ReadDid(ctx contractapi.TransactionContextInterface, did string) (*DidRecord, error) {
	if err := authorize(ctx); err != nil {
		return nil, err
	}
	if strings.TrimSpace(did) == "" {
		return nil, errors.New("did is required")
	}
	bytes, err := ctx.GetStub().GetState(did)
	if err != nil {
		return nil, err
	}
	if len(bytes) == 0 {
		return nil, fmt.Errorf("did not found: %s", did)
	}
	var record DidRecord
	if err := json.Unmarshal(bytes, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

func (c *DidRegistryContract) DeleteDid(ctx contractapi.TransactionContextInterface, did string) error {
	if err := authorize(ctx); err != nil {
		return err
	}
	if strings.TrimSpace(did) == "" {
		return errors.New("did is required")
	}
	exists, err := c.DidExists(ctx, did)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("did not found: %s", did)
	}
	if err := ctx.GetStub().DelState(did); err != nil {
		return err
	}
	payload := []byte(fmt.Sprintf("{\"did\":%q}", did))
	return ctx.GetStub().SetEvent("did.deleted", payload)
}

func (c *DidRegistryContract) DidExists(ctx contractapi.TransactionContextInterface, did string) (bool, error) {
	if strings.TrimSpace(did) == "" {
		return false, errors.New("did is required")
	}
	bytes, err := ctx.GetStub().GetState(did)
	if err != nil {
		return false, err
	}
	return len(bytes) > 0, nil
}

func authorize(ctx contractapi.TransactionContextInterface) error {
	mspID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return err
	}
	allowed := strings.TrimSpace(os.Getenv("AUNSORM_FABRIC_ALLOWED_MSPS"))
	if allowed == "" {
		return nil
	}
	for _, entry := range strings.Split(allowed, ",") {
		if strings.TrimSpace(entry) == mspID {
			return nil
		}
	}
	return fmt.Errorf("msp %s is not authorized", mspID)
}

func parseRecord(recordJSON string) (*DidRecord, error) {
	var record DidRecord
	if err := json.Unmarshal([]byte(recordJSON), &record); err != nil {
		return nil, err
	}
	if strings.TrimSpace(record.Did) == "" {
		return nil, errors.New("did is required")
	}
	if strings.TrimSpace(record.Controller) == "" {
		return nil, errors.New("controller is required")
	}
	if strings.TrimSpace(record.Channel) == "" {
		return nil, errors.New("channel is required")
	}
	if strings.TrimSpace(record.MspID) == "" {
		return nil, errors.New("mspId is required")
	}
	if strings.TrimSpace(record.VerificationMethod) == "" {
		return nil, errors.New("verificationMethod is required")
	}
	if strings.TrimSpace(record.LedgerAnchor) == "" {
		return nil, errors.New("ledgerAnchor is required")
	}
	return &record, nil
}

func writeRecord(ctx contractapi.TransactionContextInterface, record *DidRecord, event string) error {
	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState(record.Did, payload); err != nil {
		return err
	}
	return ctx.GetStub().SetEvent(event, payload)
}
