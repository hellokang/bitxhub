package coreapi

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	types2 "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	contracts2 "github.com/meshplus/bitxhub-core/eth-contracts/interchain-contracts"
	"github.com/meshplus/bitxhub-kit/types"
	"github.com/meshplus/bitxhub-model/constant"
	"github.com/meshplus/bitxhub-model/pb"
	"github.com/meshplus/bitxhub/internal/coreapi/api"
	"github.com/meshplus/bitxhub/internal/executor/contracts"
	"github.com/meshplus/bitxhub/internal/model"
	"github.com/meshplus/bitxhub/pkg/utils"
	"github.com/meshplus/eth-kit/ledger"
	solsha3 "github.com/miguelmota/go-solidity-sha3"
	"github.com/sirupsen/logrus"
)

type BrokerAPI CoreAPI

var _ api.BrokerAPI = (*BrokerAPI)(nil)

func (b *BrokerAPI) HandleTransaction(tx pb.Transaction) error {
	if tx.GetHash() == nil {
		return fmt.Errorf("transaction hash is nil")
	}

	b.logger.WithFields(logrus.Fields{
		"hash": tx.GetHash().String(),
	}).Debugf("Receive tx")

	if err := b.bxh.Order.Prepare(tx); err != nil {
		b.logger.Errorf("order prepare for tx %s failed: %s", tx.GetHash().String(), err.Error())
		return fmt.Errorf("order prepare for tx %s failed: %w", tx.GetHash().String(), err)
	}

	return nil
}

func (b *BrokerAPI) HandleView(tx pb.Transaction) (*pb.Receipt, error) {
	if tx.GetHash() == nil {
		return nil, fmt.Errorf("transaction hash is nil")
	}

	b.logger.WithFields(logrus.Fields{
		"hash": tx.GetHash().String(),
	}).Debugf("Receive view")

	receipts := b.bxh.ViewExecutor.ApplyReadonlyTransactions([]pb.Transaction{tx})

	return receipts[0], nil
}

func (b *BrokerAPI) GetTransaction(hash *types.Hash) (pb.Transaction, error) {
	return b.bxh.Ledger.GetTransaction(hash)
}

func (b *BrokerAPI) GetTransactionMeta(hash *types.Hash) (*pb.TransactionMeta, error) {
	return b.bxh.Ledger.GetTransactionMeta(hash)
}

func (b *BrokerAPI) GetReceipt(hash *types.Hash) (*pb.Receipt, error) {
	return b.bxh.Ledger.GetReceipt(hash)
}

func (b *BrokerAPI) AddPier(pierID string) (chan *pb.InterchainTxWrappers, error) {
	return b.bxh.Router.AddPier(pierID)
}

func (b *BrokerAPI) GetBlockHeader(begin, end uint64, ch chan<- *pb.BlockHeader) error {
	return b.bxh.Router.GetBlockHeader(begin, end, ch)
}

func (b *BrokerAPI) GetInterchainTxWrappers(appchainID string, begin, end uint64, ch chan<- *pb.InterchainTxWrappers) error {
	return b.bxh.Router.GetInterchainTxWrappers(appchainID, begin, end, ch)
}

func (b *BrokerAPI) GetBlock(mode string, value string) (*pb.Block, error) {
	switch mode {
	case "HEIGHT":
		height, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("wrong block number: %s", value)
		}
		return b.bxh.Ledger.GetBlock(height)
	case "HASH":
		hash := types.NewHashByStr(value)
		if hash == nil {
			return nil, fmt.Errorf("invalid format of block hash for querying block")
		}
		return b.bxh.Ledger.GetBlockByHash(hash)
	default:
		return nil, fmt.Errorf("wrong args about getting block: %s", mode)
	}
}

func (b *BrokerAPI) GetBlocks(start uint64, end uint64) ([]*pb.Block, error) {
	meta := b.bxh.Ledger.GetChainMeta()

	var blocks []*pb.Block
	if meta.Height < end {
		end = meta.Height
	}
	for i := start; i > 0 && i <= end; i++ {
		b, err := b.GetBlock("HEIGHT", strconv.Itoa(int(i)))
		if err != nil {
			continue
		}
		blocks = append(blocks, b)
	}

	return blocks, nil
}

func (b *BrokerAPI) GetBlockHeaders(start uint64, end uint64) ([]*pb.BlockHeader, error) {
	meta := b.bxh.Ledger.GetChainMeta()

	var blockHeaders []*pb.BlockHeader
	if meta.Height < end {
		end = meta.Height
	}
	for i := start; i > 0 && i <= end; i++ {
		b, err := b.GetBlock("HEIGHT", strconv.Itoa(int(i)))
		if err != nil {
			continue
		}
		blockHeaders = append(blockHeaders, b.BlockHeader)
	}

	return blockHeaders, nil
}

func (b *BrokerAPI) RemovePier(pierID string) {
	b.bxh.Router.RemovePier(pierID)
}

func (b *BrokerAPI) OrderReady() error {
	return b.bxh.Order.Ready()
}

func (b *BrokerAPI) FetchSignsFromOtherPeers(id string, typ pb.GetMultiSignsRequest_Type) map[string][]byte {
	var (
		result = make(map[string][]byte)
		wg     = sync.WaitGroup{}
		lock   = sync.Mutex{}
	)

	// TODO: calculate threshold
	wg.Add(len(b.bxh.PeerMgr.OtherPeers()))
	for pid := range b.bxh.PeerMgr.OtherPeers() {
		go func(pid uint64, result map[string][]byte, wg *sync.WaitGroup, lock *sync.Mutex) {
			var (
				address string
				sign    []byte
				err     error
			)
			switch typ {
			case pb.GetMultiSignsRequest_IBTP_REQUEST:
				fallthrough
			case pb.GetMultiSignsRequest_IBTP_RESPONSE:
				address, sign, err = b.requestIBTPSignPeer(pid, id, typ)
			case pb.GetMultiSignsRequest_BLOCK_HEADER:
				address, sign, err = b.requestBlockHeaderSignFromPeer(pid, id)
			case pb.GetMultiSignsRequest_BURN:
				address, sign, err = b.requestBurnSignFromPeer(pid, id)
			}

			if err != nil {
				b.logger.WithFields(logrus.Fields{
					"pid": pid,
					"err": err.Error(),
				}).Warnf("Get multi-sign with error")
			} else {
				lock.Lock()
				result[address] = sign
				lock.Unlock()
			}
			wg.Done()
		}(pid, result, &wg, &lock)
	}

	wg.Wait()

	return result
}

func (b *BrokerAPI) requestIBTPSignPeer(pid uint64, id string, typ pb.GetMultiSignsRequest_Type) (string, []byte, error) {
	req := pb.Message{
		Type: pb.Message_FETCH_IBTP_REQUEST_SIGN,
		Data: []byte(id),
	}
	if typ == pb.GetMultiSignsRequest_IBTP_RESPONSE {
		req.Type = pb.Message_FETCH_IBTP_RESPONSE_SIGN
	}

	resp, err := b.bxh.PeerMgr.Send(pid, &req)
	if err != nil {
		return "", nil, fmt.Errorf("send message to %d failed: %w", pid, err)
	}
	if resp == nil || resp.Type != pb.Message_FETCH_IBTP_SIGN_ACK {
		return "", nil, fmt.Errorf("invalid fetch ibtp sign resp")
	}

	data := model.MerkleWrapperSign{}
	if err := data.Unmarshal(resp.Data); err != nil {
		return "", nil, fmt.Errorf("unmarshal merkle wrapper sign error: %w", err)
	}

	return data.Address, data.Signature, nil
}

func (b *BrokerAPI) requestBlockHeaderSignFromPeer(pid uint64, height string) (string, []byte, error) {
	req := pb.Message{
		Type: pb.Message_FETCH_BLOCK_SIGN,
		Data: []byte(height),
	}

	resp, err := b.bxh.PeerMgr.Send(pid, &req)
	if err != nil {
		return "", nil, fmt.Errorf("send message to %d failed: %w", pid, err)
	}

	if resp == nil || resp.Type != pb.Message_FETCH_BLOCK_SIGN_ACK {
		return "", nil, fmt.Errorf("invalid fetch block header sign resp")
	}

	data := model.MerkleWrapperSign{}
	if err := data.Unmarshal(resp.Data); err != nil {
		return "", nil, fmt.Errorf("unmarsahl merkle wrapper sign error: %w", err)
	}

	return data.Address, data.Signature, nil
}

func (b *BrokerAPI) requestBurnSignFromPeer(pid uint64, hash string) (string, []byte, error) {
	req := pb.Message{
		Type: pb.Message_FETCH_BURN_SIGN,
		Data: []byte(hash),
	}

	resp, err := b.bxh.PeerMgr.Send(pid, &req)
	if err != nil {
		return "", nil, fmt.Errorf("send message to %d failed: %w", pid, err)
	}

	if resp == nil || resp.Type != pb.Message_FETCH_BURN_SIGN_ACK {
		return "", nil, fmt.Errorf("invalid fetch minter sign resp")
	}

	data := model.MerkleWrapperSign{}
	if err := data.Unmarshal(resp.Data); err != nil {
		return "", nil, fmt.Errorf("unmarshal merkle wrapper sign error: %w", err)
	}

	return data.Address, data.Signature, nil
}

func (b *BrokerAPI) GetSign(content string, typ pb.GetMultiSignsRequest_Type) (string, []byte, error) {
	switch typ {
	case pb.GetMultiSignsRequest_IBTP_REQUEST:
		return utils.GetIBTPSign(b.bxh.Ledger, content, true, b.bxh.GetPrivKey().PrivKey)
	case pb.GetMultiSignsRequest_IBTP_RESPONSE:
		return utils.GetIBTPSign(b.bxh.Ledger, content, false, b.bxh.GetPrivKey().PrivKey)
	case pb.GetMultiSignsRequest_BLOCK_HEADER:
		height, err := strconv.ParseUint(content, 10, 64)
		if err != nil {
			return "", nil, fmt.Errorf("get block header sign: %w", err)
		}

		sign, err := b.bxh.Ledger.GetBlockSign(height)
		if err != nil {
			return "", nil, fmt.Errorf("get block sign: %w", err)
		}

		return b.bxh.GetPrivKey().Address, sign, nil
	case pb.GetMultiSignsRequest_BURN:
		return b.handleMultiSignsBurnReq(content)
	default:
		return "", nil, fmt.Errorf("unsupported get sign type")
	}
}

func (b *BrokerAPI) handleMultiSignsBurnReq(hash string) (string, []byte, error) {
	receipt, err := b.bxh.Ledger.GetReceipt(types.NewHashByStr(hash))
	if err != nil {
		return "", nil, fmt.Errorf("cannot find receipt with hash %s", hash)
	}
	ok, interchainSwapAddr := b.bxh.Ledger.GetState(constant.EthHeaderMgrContractAddr.Address(), []byte(contracts.InterchainSwapAddrKey))
	if !ok {
		return "", nil, fmt.Errorf("cannot find interchainswap contract")
	}

	addr := &contracts.ContractAddr{}
	err = json.Unmarshal(interchainSwapAddr, &addr)
	if err != nil {
		return "", nil, fmt.Errorf("unmarshal contract addr error: %w", err)
	}
	var burn *contracts2.InterchainSwapBurn
	for _, log := range receipt.GetEvmLogs() {
		if !strings.EqualFold(log.Address.String(), addr.Addr) {
			continue
		}

		if log.Removed {
			continue
		}

		interchainSwap, err := contracts2.NewInterchainSwap(common.Address{}, nil)
		if err != nil {
			continue
		}
		data, err := json.Marshal(log)
		if err != nil {
			continue
		}
		ethLog := &types2.Log{}
		err = json.Unmarshal(data, &ethLog)
		if err != nil {
			continue
		}
		burn, err = interchainSwap.ParseBurn(*ethLog)
		if err != nil {
			continue
		}
	}

	if burn == nil {
		return "", nil, fmt.Errorf("not found burn log:%v", receipt.TxHash.Hash)
	}

	//abi.encodePacked
	abiHash := solsha3.SoliditySHA3(
		solsha3.Address(burn.AppToken.String()),
		solsha3.Address(burn.Burner.String()),
		solsha3.Address(burn.Recipient.String()),
		solsha3.Uint256(burn.Amount),
		solsha3.String(hash),
	)

	prefixedHash := crypto.Keccak256Hash(
		[]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%v", len(abiHash))),
		abiHash,
	)
	key := b.bxh.GetPrivKey()

	sign, err := key.PrivKey.Sign(prefixedHash[:])
	if err != nil {
		return "", nil, fmt.Errorf("bitxhub sign: %w", err)
	}

	return key.Address, sign, nil
}

func (b BrokerAPI) GetPendingNonceByAccount(account string) uint64 {
	return b.bxh.Order.GetPendingNonceByAccount(account)
}

func (b BrokerAPI) GetPendingTransactions(max int) []pb.Transaction {
	// TODO
	return nil
}

func (b BrokerAPI) GetPoolTransaction(hash *types.Hash) pb.Transaction {
	return b.bxh.Order.GetPendingTxByHash(hash)
}

func (b BrokerAPI) GetStateLedger() ledger.StateLedger {
	return b.bxh.Ledger.StateLedger
}
