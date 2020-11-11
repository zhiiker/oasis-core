package governance

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	governanceState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/governance/state"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

func TestSubmitProposal(t *testing.T) {
	require := require.New(t)
	var err error

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextDeliverTx, now)
	defer ctx.Close()

	// Setup staking state.
	stakeState := stakingState.NewMutableState(ctx.State())
	pk1 := signature.NewPublicKey("aaafffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr1 := staking.NewAddress(pk1)
	noFundsPk := signature.NewPublicKey("f00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	reservedPK := signature.NewPublicKey("badaafffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	_ = staking.NewReservedAddress(reservedPK)

	// Configure an balance for pk1.
	err = stakeState.SetAccount(ctx, addr1, &staking.Account{
		General: staking.GeneralAccount{
			Balance: *quantity.NewFromUint64(200),
		},
	})
	require.NoError(err, "SetAccount")

	// Setup governance state.
	state := governanceState.NewMutableState(ctx.State())
	app := &governanceApplication{
		state: appState,
	}

	minProposalDeposit := quantity.NewQuantity()
	require.NoError(minProposalDeposit.FromUint64(100))
	baseConsParams := &governance.ConsensusParameters{
		GasCosts:                  governance.DefaultGasCosts,
		MinProposalDeposit:        *minProposalDeposit,
		Quorum:                    90,
		Threshold:                 90,
		UpgradeCancelMinEpochDiff: epochtime.EpochTime(100),
		UpgradeMinEpochDiff:       epochtime.EpochTime(100),
		VotingPeriod:              epochtime.EpochTime(50),
	}

	for _, tc := range []struct {
		msg             string
		params          *governance.ConsensusParameters
		txSigner        signature.PublicKey
		proposalContent *governance.ProposalContent
		prepareFn       func()
		err             error
	}{
		{
			"should fail with malformed proposal content",
			baseConsParams,
			pk1,
			&governance.ProposalContent{},
			func() {},
			governance.ErrInvalidArgument,
		},
		{
			"should fail with reserved submitter address",
			baseConsParams,
			reservedPK,
			&governance.ProposalContent{Upgrade: &governance.UpgradeProposal{}},
			func() {},
			staking.ErrForbidden,
		},
		{
			"should fail with insufficient submitter balance",
			baseConsParams,
			noFundsPk,
			&governance.ProposalContent{Upgrade: &governance.UpgradeProposal{}},
			func() {},
			staking.ErrInsufficientBalance,
		},
		{
			"should fail with invalid upgrade proposal",
			baseConsParams,
			pk1,
			&governance.ProposalContent{Upgrade: &governance.UpgradeProposal{}},
			func() {},
			governance.ErrInvalidArgument,
		},
		{
			"should fail with invalid upgrade proposal scheduled for to soon",
			baseConsParams,
			pk1,
			&governance.ProposalContent{Upgrade: &governance.UpgradeProposal{
				Descriptor: upgrade.Descriptor{
					Method: upgrade.UpgradeMethInternal,
					Epoch:  10,
				},
			}},
			func() {},
			governance.ErrUpgradeTooSoon,
		},
		{
			"should fail cancel upgrade proposal for non-existing pending upgrade",
			baseConsParams,
			pk1,
			&governance.ProposalContent{CancelUpgrade: &governance.CancelUpgradeProposal{
				ProposalID: 10,
			}},
			func() {},
			governance.ErrNoSuchProposal,
		},
		{
			"should fail cancel upgrade proposal for pending upgrade scheduled to soon",
			baseConsParams,
			pk1,
			&governance.ProposalContent{CancelUpgrade: &governance.CancelUpgradeProposal{
				ProposalID: 10,
			}},
			func() {
				upgrade := upgrade.Descriptor{
					Method: upgrade.UpgradeMethInternal,
					Epoch:  10,
				}
				err = state.SetPendingUpgrade(ctx, 10, &upgrade)
				require.NoError(err, "SetPendingUpgrade()")
				err = state.SetProposal(ctx, &governance.Proposal{
					ID: 10,
					Content: governance.ProposalContent{
						Upgrade: &governance.UpgradeProposal{
							Descriptor: upgrade,
						},
					},
				})
				require.NoError(err, "SetProposal()")
			},
			governance.ErrUpgradeTooSoon,
		},
		{
			"should work with valid upgrade descriptor",
			baseConsParams,
			pk1,
			&governance.ProposalContent{Upgrade: &governance.UpgradeProposal{
				Descriptor: upgrade.Descriptor{
					Method: upgrade.UpgradeMethInternal,
					Epoch:  200,
				},
			}},
			func() {},
			nil,
		},
		{
			"should work with valid cancel upgrade proposal",
			baseConsParams,
			pk1,
			&governance.ProposalContent{CancelUpgrade: &governance.CancelUpgradeProposal{
				ProposalID: 20,
			}},
			func() {
				upgrade := upgrade.Descriptor{
					Method: upgrade.UpgradeMethInternal,
					Epoch:  500,
				}
				err = state.SetPendingUpgrade(ctx, 20, &upgrade)
				require.NoError(err, "SetPendingUpgrade()")
				err = state.SetProposal(ctx, &governance.Proposal{
					ID: 20,
					Content: governance.ProposalContent{
						Upgrade: &governance.UpgradeProposal{
							Descriptor: upgrade,
						},
					},
				})
				require.NoError(err, "SetProposal()")
			},
			nil,
		},
	} {
		err = state.SetConsensusParameters(ctx, tc.params)
		require.NoError(err, "setting governance consensus parameters should not error")

		ctx.SetTxSigner(tc.txSigner)

		tc.prepareFn()

		var governanceDepositsBefore, governanceDepositsAfter *quantity.Quantity
		governanceDepositsBefore, err = stakeState.GovernanceDeposits(ctx)
		require.NoError(err, "GovernanceDeposits()")

		err = app.submitProposal(ctx, state, tc.proposalContent)
		require.Equal(tc.err, err, tc.msg)

		// If proposal passed, ensure proposal deposit was made.
		if tc.err == nil {
			governanceDepositsAfter, err = stakeState.GovernanceDeposits(ctx)
			require.NoError(err, "GovernanceDeposits()")

			err = governanceDepositsAfter.Sub(governanceDepositsBefore)
			require.NoError(err, "quantity.Sub")
			require.EqualValues(&tc.params.MinProposalDeposit, governanceDepositsAfter, tc.msg)

		}
	}
}

func TestCastVote(t *testing.T) {
	// TODO:
}
