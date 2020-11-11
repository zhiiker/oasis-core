package governance

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	schedulerState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/scheduler/state"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func TestValidatorsEscrow(t *testing.T) {
	require := require.New(t)
	var err error

	numAccounts := 5
	accountStake := quantity.NewFromUint64(100)

	// Each account has same amount escrowed. First account is not in validator committee.
	expectedTotalStake := accountStake.Clone()
	err = expectedTotalStake.Mul(quantity.NewFromUint64(uint64(numAccounts - 1)))
	require.NoError(err, "Mul")
	expectedValidatorsEscrow := make(map[staking.Address]*quantity.Quantity)

	// Setup state.
	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextDeliverTx, now)
	defer ctx.Close()

	registryState := registryState.NewMutableState(ctx.State())
	stakingState := stakingState.NewMutableState(ctx.State())
	schedulerState := schedulerState.NewMutableState(ctx.State())

	// Prepare some entities and nodes.
	validatorSet := make(map[signature.PublicKey]int64)
	for i := 0; i < numAccounts; i++ {
		nodeSigner := memorySigner.NewTestSigner(fmt.Sprintf("consensus/tendermint/apps/governance: node signer: %d", i))
		entitySigner := memorySigner.NewTestSigner(fmt.Sprintf("consensus/tendermint/apps/governance: entity signer: %d", i))

		ent := entity.Entity{
			Versioned: cbor.NewVersioned(entity.LatestEntityDescriptorVersion),
			ID:        entitySigner.Public(),
			Nodes:     []signature.PublicKey{nodeSigner.Public()},
		}
		sigEnt, entErr := entity.SignEntity(entitySigner, registry.RegisterEntitySignatureContext, &ent)
		require.NoError(entErr, "SignEntity")
		err = registryState.SetEntity(ctx, &ent, sigEnt)
		require.NoError(err, "SetEntity")

		nod := &node.Node{
			Versioned: cbor.NewVersioned(node.LatestNodeDescriptorVersion),
			ID:        nodeSigner.Public(),
			EntityID:  entitySigner.Public(),
		}
		sigNode, nErr := node.MultiSignNode([]signature.Signer{nodeSigner}, registry.RegisterNodeSignatureContext, nod)
		require.NoError(nErr, "MultiSignNode")
		err = registryState.SetNode(ctx, nil, nod, sigNode)
		require.NoError(err, "SetNode")

		// Set all but first node as a validator
		if i > 0 {
			validatorSet[nodeSigner.Public()] = 1
		}

		// Setup entity escrow.
		// Configure an balance.
		addr := staking.NewAddress(entitySigner.Public())
		err = stakingState.SetAccount(ctx, addr, &staking.Account{
			Escrow: staking.EscrowAccount{
				Active: staking.SharePool{
					TotalShares: *quantity.NewFromUint64(100),
					Balance:     *accountStake,
				},
			},
		})
		require.NoError(err, "SetAccount")

		// Update expected values.
		if i > 0 {
			// First node is not in the validator set.
			expectedValidatorsEscrow[addr] = accountStake
		}
	}
	err = schedulerState.PutCurrentValidators(ctx, validatorSet)
	require.NoError(err, "PutCurrentValidators")

	// Test validatorsEscrow.
	app := &governanceApplication{
		state: appState,
	}
	totalStake, validatorsEscrow, err := app.validatorsEscrow(ctx, stakingState, registryState, schedulerState)
	require.NoError(err, "app.validatorsEscrow()")
	require.EqualValues(expectedTotalStake, totalStake, "total stake should match expected")
	require.EqualValues(expectedValidatorsEscrow, validatorsEscrow, "validators escrow should match expected")
}

func TestProposalDeposits(t *testing.T) {
	// Setup state.
	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextDeliverTx, now)
	defer ctx.Close()

	stakingState := stakingState.NewMutableState(ctx.State())
	pk1 := signature.NewPublicKey("aaafffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr1 := staking.NewAddress(pk1)
	pk2 := signature.NewPublicKey("bbbfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr2 := staking.NewAddress(pk2)

	// Configure balances.
	err := stakingState.SetAccount(ctx, addr1, &staking.Account{
		General: staking.GeneralAccount{
			Balance: *quantity.NewFromUint64(200),
		},
	})
	require.NoError(t, err, "SetAccount")
	err = stakingState.SetAccount(ctx, addr2, &staking.Account{
		General: staking.GeneralAccount{
			Balance: *quantity.NewFromUint64(200),
		},
	})
	require.NoError(t, err, "SetAccount")

	err = stakingState.SetGovernanceDeposits(ctx, quantity.NewFromUint64(0))
	require.NoError(t, err, "SetGovernanceDeposits")

	app := &governanceApplication{
		state: appState,
	}

	// Test proposal deposit.
	err = app.doProposalDeposit(ctx, stakingState, addr1, quantity.NewFromUint64(10))
	require.NoError(t, err, "doProposalDeposit")

	err = app.doProposalDeposit(ctx, stakingState, addr2, quantity.NewFromUint64(20))
	require.NoError(t, err, "doProposalDeposit")

	var deposits *quantity.Quantity
	deposits, err = stakingState.GovernanceDeposits(ctx)
	require.NoError(t, err, "GovernanceDeposits")
	require.EqualValues(t, quantity.NewFromUint64(30), deposits, "expected governance deposit should be made")

	var acc1 *staking.Account
	acc1, err = stakingState.Account(ctx, addr1)
	require.NoError(t, err, "Account")
	require.EqualValues(t, *quantity.NewFromUint64(190), acc1.General.Balance, "expected governance deposit should be made")

	var acc2 *staking.Account
	acc2, err = stakingState.Account(ctx, addr2)
	require.NoError(t, err, "Account")
	require.EqualValues(t, *quantity.NewFromUint64(180), acc2.General.Balance, "expected governance deposit should be made")

	// Discard pk1 deposit.
	err = app.discardProposalDeposit(ctx, stakingState, quantity.NewFromUint64(10))
	require.NoError(t, err, "discardProposalDeposit")

	// Reclaim pk2 deposit.
	err = app.reclaimProposalDeposit(ctx, stakingState, addr2, quantity.NewFromUint64(20))
	require.NoError(t, err, "reclaimProposalDeposit")

	// Ensure final ballances are correct.
	deposits, err = stakingState.CommonPool(ctx)
	require.NoError(t, err, "CommonPool")
	require.EqualValues(t, quantity.NewFromUint64(10), deposits, "governance funds should be discarded into the common pool")

	deposits, err = stakingState.GovernanceDeposits(ctx)
	require.NoError(t, err, "GovernanceDeposits")
	require.EqualValues(t, quantity.NewFromUint64(0), deposits, "governance deposits should be empty")

	acc1, err = stakingState.Account(ctx, addr1)
	require.NoError(t, err, "Account")
	require.EqualValues(t, *quantity.NewFromUint64(190), acc1.General.Balance, "governance deposit should be discarded")

	acc2, err = stakingState.Account(ctx, addr2)
	require.NoError(t, err, "Account")
	require.EqualValues(t, *quantity.NewFromUint64(200), acc2.General.Balance, "governance deposit should be reclaimed")
}

func TestCloseProposal(t *testing.T) {
	// TODO:
}

func TestExecuteProposal(t *testing.T) {
	// TODO:
}
