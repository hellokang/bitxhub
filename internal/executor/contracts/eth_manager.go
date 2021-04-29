package contracts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/meshplus/bitxhub-core/boltvm"
	"github.com/meshplus/bitxhub/internal/executor/oracle/appchain"
	"github.com/sirupsen/logrus"
)

const (
	EscrowsAddrKey        = "escrows_addr_key"
	InterchainSwapAddrKey = "interchain_swap_addr_key"
	MINT_HASH_PREFIX      = "mint"
	ETH_TX_HASH_PREFIX    = "eth-hash"
)

type ContractAddr struct {
	Addr string `json:"addr"`
}

type EthHeaderManager struct {
	boltvm.Stub
	oracle *appchain.EthLightChainOracle
}

func NewEthHeaderManager(path string, logger logrus.FieldLogger) *EthHeaderManager {
	ropstenOracle, err := appchain.NewRopstenOracle(path, logger)
	if err != nil {
		panic(err)
	}
	return &EthHeaderManager{oracle: ropstenOracle}
}

func (ehm *EthHeaderManager) SetEscrowAddr(addr string) *boltvm.Response {
	//TODO:add governance
	ok := common.IsHexAddress(addr)
	if ok {
		escrowsAddr := ContractAddr{addr}
		ehm.SetObject(EscrowsAddrKey, escrowsAddr)
	}
	return boltvm.Success([]byte(addr))
}

func (ehm *EthHeaderManager) GetEscrowAddr() *boltvm.Response {
	var escrowsAddr ContractAddr
	ok := ehm.GetObject(EscrowsAddrKey, escrowsAddr)
	if ok {
		return boltvm.Success([]byte(escrowsAddr.Addr))
	}
	return boltvm.Error("not found")
}

func (ehm *EthHeaderManager) SetInterchainSwapAddr(addr string) *boltvm.Response {
	//TODO:add governance
	ok := common.IsHexAddress(addr)
	if ok {
		interchainSwapAddr := ContractAddr{addr}
		ehm.SetObject(InterchainSwapAddrKey, interchainSwapAddr)
	}
	return boltvm.Success([]byte(addr))
}

func (ehm *EthHeaderManager) GetInterchainSwapAddr() *boltvm.Response {
	var interchainSwapAddr ContractAddr
	ok := ehm.GetObject(InterchainSwapAddrKey, interchainSwapAddr)
	if ok {
		return boltvm.Success([]byte(interchainSwapAddr.Addr))
	}
	return boltvm.Error("not found")
}

func (ehm *EthHeaderManager) InsertBlockHeaders(headersData []byte) *boltvm.Response {
	headers := make([]*types.Header, 0)
	err := json.Unmarshal(headersData, &headers)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	num, err := ehm.oracle.InsertBlockHeaders(headers)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success([]byte(strconv.Itoa(num)))
}

func (ehm *EthHeaderManager) CurrentBlockHeader() *boltvm.Response {
	header := ehm.oracle.CurrentHeader()
	if header == nil {
		return boltvm.Error("not found")
	}
	data, err := header.MarshalJSON()
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success(data)
}

func (ehm *EthHeaderManager) GetBlockHeader(hash string) *boltvm.Response {
	header := ehm.oracle.GetHeader(common.HexToHash(hash))
	if header == nil {
		return boltvm.Error("not found")
	}
	data, err := header.MarshalJSON()
	if err != nil {
		return boltvm.Error(err.Error())
	}
	return boltvm.Success(data)
}

func (ehm *EthHeaderManager) PreMint(receiptData []byte, proofData []byte) *boltvm.Response {
	var receipt types.Receipt
	err := receipt.UnmarshalJSON(receiptData)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	ok, v := ehm.Get(EthTxKey(receipt.TxHash.String()))
	if ok {
		return boltvm.Success(v)
	}

	err = ehm.oracle.VerifyProof(&receipt, proofData)
	if err != nil {
		return boltvm.Error(err.Error())
	}
	escrowsLockEvent, err := ehm.unpackEscrowsLock(&receipt)
	if err != nil {
		return boltvm.Error(err.Error())
	}

	//abi.encodePacked
	hash := crypto.Keccak256Hash(
		escrowsLockEvent.EthToken.Bytes(),
		escrowsLockEvent.RelayToken.Bytes(),
		escrowsLockEvent.Locker.Bytes(),
		escrowsLockEvent.Recipient.Bytes(),
		receipt.TxHash.Bytes(),
		common.LeftPadBytes(escrowsLockEvent.Amount.Bytes(), 32),
	)
	prefixedHash := crypto.Keccak256Hash(
		[]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%v", len(hash))),
		hash.Bytes(),
	)
	ehm.SetObject(MintKey(prefixedHash.String()), escrowsLockEvent)
	ehm.Set(EthTxKey(receipt.TxHash.String()), prefixedHash.Bytes())
	return boltvm.Success(prefixedHash.Bytes())
}

func (ehm *EthHeaderManager) GetPrefixedHash(hash string) *boltvm.Response {
	ok, v := ehm.Get(EthTxKey(hash))
	if ok {
		return boltvm.Success(v)
	}
	return boltvm.Error(fmt.Sprintf("not found prefixed hash by %v", hash))
}

func (ehm *EthHeaderManager) unpackEscrowsLock(receipt *types.Receipt) (*appchain.EscrowsLock, error) {
	escrowsAbi, err := abi.JSON(bytes.NewReader([]byte(appchain.EscrowsABI)))
	if err != nil {
		return nil, err
	}
	var escrowsAddr ContractAddr
	ok := ehm.GetObject(EscrowsAddrKey, escrowsAddr)
	if !ok {
		return nil, fmt.Errorf("not found the escrows contract address")
	}
	var lock *appchain.EscrowsLock
	for _, log := range receipt.Logs {
		if !strings.EqualFold(log.Address.String(), escrowsAddr.Addr) {
			continue
		}

		if log.Removed {
			continue
		}
		for _, topic := range log.Topics {
			if strings.EqualFold(topic.String(), escrowsAbi.Events["Lock"].ID.String()) {
				if err := escrowsAbi.UnpackIntoInterface(&lock, "Lock", log.Data); err != nil {
					continue
				}
			}
		}
	}
	if lock == nil {
		return nil, fmt.Errorf("not found the escrow lock event")
	}
	return lock, nil
}

func MintKey(hash string) string {
	return fmt.Sprintf("%s-%s", MINT_HASH_PREFIX, hash)
}

func EthTxKey(hash string) string {
	return fmt.Sprintf("%s-%s", ETH_TX_HASH_PREFIX, hash)
}
