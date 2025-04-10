package genesis

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/iancoleman/orderedmap"
	"github.com/meshplus/bitxhub-core/governance"
	node_mgr "github.com/meshplus/bitxhub-core/node-mgr"
	"github.com/meshplus/bitxhub-kit/types"
	"github.com/meshplus/bitxhub-model/constant"
	"github.com/meshplus/bitxhub-model/pb"
	"github.com/meshplus/bitxhub/internal/executor"
	"github.com/meshplus/bitxhub/internal/executor/contracts"
	"github.com/meshplus/bitxhub/internal/ledger"
	"github.com/meshplus/bitxhub/internal/repo"
)

// Initialize initialize block
func Initialize(genesis *repo.Genesis, nodes []*repo.NetworkNodes, primaryN uint64, lg *ledger.Ledger, executor executor.Executor) error {
	lg.PrepareBlock(nil, 1)

	// init super governance admin
	idMap := map[string]struct{}{}
	for _, ad := range genesis.Admins {
		idMap[ad.Address] = struct{}{}
		admin := &contracts.Role{
			ID:       ad.Address,
			RoleType: contracts.GovernanceAdmin,
			Weight:   ad.Weight,
			Status:   governance.GovernanceAvailable,
		}
		adminData, err := json.Marshal(admin)
		if err != nil {
			return fmt.Errorf("marshal admin data error: %w", err)
		}
		lg.SetState(constant.RoleContractAddr.Address(), []byte(contracts.RoleKey(admin.ID)), adminData)
	}
	idMapData, err := json.Marshal(idMap)
	if err != nil {
		return fmt.Errorf("marshal id map data error: %w", err)
	}
	lg.SetState(constant.RoleContractAddr.Address(), []byte(contracts.RoleTypeKey(string(contracts.GovernanceAdmin))), idMapData)

	// init super governance admin balance
	balance, _ := new(big.Int).SetString(genesis.Balance, 10)
	for _, admin := range genesis.Admins {
		lg.SetBalance(types.NewAddressByStr(admin.Address), balance)
	}
	lg.SetState(constant.RoleContractAddr.Address(), []byte(contracts.GenesisBalance), []byte(genesis.Balance))

	for _, v := range genesis.Strategy {
		ps := &contracts.ProposalStrategy{
			Module: v.Module,
			Typ:    contracts.ProposalStrategyType(v.Typ),
			Extra:  v.Extra,
			Status: governance.GovernanceAvailable,
		}
		psData, err := json.Marshal(ps)
		if err != nil {
			return err
		}
		lg.SetState(constant.ProposalStrategyMgrContractAddr.Address(), []byte(contracts.ProposalStrategyKey(v.Module)), psData)
	}

	// init primary vp node
	nodeAccountMap := orderedmap.New()
	for i := 0; i < int(primaryN); i++ {
		node := &node_mgr.Node{
			Account:  nodes[i].Account,
			NodeType: node_mgr.VPNode,
			Pid:      nodes[i].Pid,
			VPNodeId: nodes[i].ID,
			Primary:  true,
			Status:   governance.GovernanceAvailable,
		}
		nodeData, err := json.Marshal(node)
		if err != nil {
			return fmt.Errorf("marshal node data error: %w", err)
		}
		lg.SetState(constant.NodeManagerContractAddr.Address(), []byte(node_mgr.NodeKey(node.Account)), nodeData)
		lg.SetState(constant.NodeManagerContractAddr.Address(), []byte(node_mgr.VpNodeIdKey(strconv.Itoa(int(node.VPNodeId)))), []byte(node.Account))
		lg.SetState(constant.NodeManagerContractAddr.Address(), []byte(node_mgr.VpNodePidKey(node.Pid)), []byte(node.Account))
		nodeAccountMap.Set(node.Account, struct{}{})
	}
	nodeAccountMapData, err := json.Marshal(nodeAccountMap)
	if err != nil {
		return fmt.Errorf("marshal node account map data error: %w", err)
	}
	lg.SetState(constant.NodeManagerContractAddr.Address(), []byte(node_mgr.NodeTypeKey(string(node_mgr.VPNode))), nodeAccountMapData)

	// init bitxhub id
	lg.SetState(constant.InterchainContractAddr.Address(), []byte(contracts.BitXHubID), []byte(fmt.Sprintf("%d", genesis.ChainID)))

	// avoid being deleted by complex state ledger
	for addr := range executor.GetBoltContracts() {
		lg.SetNonce(types.NewAddressByStr(addr), 1)
	}

	accounts, stateRoot := lg.FlushDirtyData()

	block := &pb.Block{
		BlockHeader: &pb.BlockHeader{
			Number:      1,
			StateRoot:   stateRoot,
			TxRoot:      &types.Hash{},
			ReceiptRoot: &types.Hash{},
			ParentHash:  &types.Hash{},
			Bloom:       &types.Bloom{},
			Timestamp:   time.Now().UnixNano(),
		},
		Transactions: &pb.Transactions{},
	}
	block.BlockHash = block.Hash()
	blockData := &ledger.BlockData{
		Block:          block,
		Receipts:       nil,
		Accounts:       accounts,
		InterchainMeta: &pb.InterchainMeta{},
	}

	lg.PersistBlockData(blockData)

	return nil
}
