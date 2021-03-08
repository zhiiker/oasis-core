package api

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"

	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func TestValidatorConversionTopK(t *testing.T) {
	require := require.New(t)

	mkacct := func(balance uint64) *staking.Account {
		return &staking.Account{
			Escrow: staking.EscrowAccount{
				Active: staking.SharePool{
					Balance: *quantity.NewFromUint64(balance),
				},
			},
		}
	}

	mkent := func(num int) (entity.Entity, *entity.SignedEntity) {
		ents := memorySigner.NewTestSigner(fmt.Sprintf("test entity %d", num))
		e := entity.Entity{
			ID: ents.Public(),
		}
		se, err := entity.SignEntity(ents, registry.RegisterGenesisEntitySignatureContext, &e)
		if err != nil {
			panic(err)
		}
		return e, se
	}

	mknod := func(ent entity.Entity, num int) *node.MultiSignedNode {
		nods := memorySigner.NewTestSigner(fmt.Sprintf("test node %d", num))
		n := node.Node{
			ID:       nods.Public(),
			EntityID: ent.ID,
			Roles:    node.RoleValidator,
			Consensus: node.ConsensusInfo{
				ID: nods.Public(),
			},
		}
		sn, err := node.MultiSignNode(
			[]signature.Signer{nods},
			registry.RegisterGenesisNodeSignatureContext,
			&n,
		)
		if err != nil {
			panic(err)
		}
		return sn
	}

	e0, se0 := mkent(0)
	e1, se1 := mkent(1)
	e2, se2 := mkent(2)
	e3, se3 := mkent(3)
	e4, se4 := mkent(4)
	e5, se5 := mkent(5)

	sn0 := mknod(e0, 0)
	sn1 := mknod(e1, 1)
	sn2 := mknod(e2, 2)
	sn3 := mknod(e3, 3)
	sn4 := mknod(e4, 4)
	sn5 := mknod(e4, 5)

	base := scheduler.BaseUnitsPerVotingPower.ToBigInt().Uint64()

	doc := &genesis.Document{
		Scheduler: scheduler.Genesis{
			Parameters: scheduler.ConsensusParameters{
				MinValidators:          1,
				MaxValidators:          4,
				MaxValidatorsPerEntity: 1,
			},
		},
		Registry: registry.Genesis{
			Entities: []*entity.SignedEntity{
				se0, se1, se2, se3, se4, se5,
			},
			Nodes: []*node.MultiSignedNode{
				sn0, sn1, sn2, sn3, sn4, sn5,
			},
		},
		Staking: staking.Genesis{
			Ledger: map[staking.Address]*staking.Account{
				staking.NewAddress(e0.ID): mkacct(0),
				staking.NewAddress(e1.ID): mkacct(base * 2000),
				staking.NewAddress(e2.ID): mkacct(base * 3000),
				staking.NewAddress(e3.ID): mkacct(base * 4000),
				staking.NewAddress(e4.ID): mkacct(base * 5000),
				staking.NewAddress(e5.ID): mkacct(base * 6000),
			},
		},
	}

	converted, err := convertValidators(doc)
	require.NoError(err)
	require.NotNil(converted)
	require.EqualValues(doc.Scheduler.Parameters.MaxValidators, len(converted))

	require.EqualValues(converted[0].Power, 5000)
	require.EqualValues(converted[1].Power, 4000)
	require.EqualValues(converted[2].Power, 3000)
	require.EqualValues(converted[3].Power, 2000)
}