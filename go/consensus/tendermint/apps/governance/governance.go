package governance

import (
	"fmt"

	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	governanceState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/governance/state"
	registryapp "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	schedulerapp "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/scheduler"
	schedulerState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/scheduler/state"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking"
	stakingapp "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	stakingAPI "github.com/oasisprotocol/oasis-core/go/staking/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

var _ api.Application = (*governanceApplication)(nil)

type governanceApplication struct {
	state api.ApplicationState
}

func (app *governanceApplication) Name() string {
	return AppName
}

func (app *governanceApplication) ID() uint8 {
	return AppID
}

func (app *governanceApplication) Methods() []transaction.MethodName {
	return governance.Methods
}

func (app *governanceApplication) Blessed() bool {
	return false
}

func (app *governanceApplication) Dependencies() []string {
	return []string{registryapp.AppName, schedulerapp.AppName, stakingapp.AppName}
}

func (app *governanceApplication) OnRegister(state api.ApplicationState) {
	app.state = state
}

func (app *governanceApplication) OnCleanup() {
}

func (app *governanceApplication) ExecuteTx(ctx *api.Context, tx *transaction.Transaction) error {
	state := governanceState.NewMutableState(ctx.State())

	switch tx.Method {
	case governance.SubmitProposal:
		var proposalContent governance.ProposalContent
		if err := cbor.Unmarshal(tx.Body, &proposalContent); err != nil {
			return err
		}
		return app.submitProposal(ctx, state, &proposalContent)
	case governance.CastVote:
		var proposalVote governance.ProposalVote
		if err := cbor.Unmarshal(tx.Body, &proposalVote); err != nil {
			return err
		}
		return app.castVote(ctx, state, &proposalVote)
	default:
		return governance.ErrInvalidArgument
	}
}

func (app *governanceApplication) ForeignExecuteTx(ctx *api.Context, other api.Application, tx *transaction.Transaction) error {
	return nil
}

func (app *governanceApplication) BeginBlock(ctx *api.Context, request types.RequestBeginBlock) error {
	// Check if epoch has changed.
	epochChanged, epoch := app.state.EpochChanged(ctx)
	if !epochChanged {
		// Nothing to do.
		return nil
	}

	// Check if a pending upgrade is scheduled for current epoch.
	state := governanceState.NewMutableState(ctx.State())
	pendingUpgrades, err := state.PendingUpgrades(ctx)
	if err != nil {
		return fmt.Errorf("tendermint/governance: couldn't get pending upgrades: %w", err)
	}
	var upgrade *upgrade.Descriptor
	for _, pendingUpgrade := range pendingUpgrades {
		if pendingUpgrade.Epoch == epoch {
			upgrade = pendingUpgrade
			break
		}
	}
	if upgrade == nil {
		// No upgrade scheduled for current epoch.
		return nil
	}

	// TODO?

	// In case it is and we are not running the new version, the consensus layer will panic.
	// Otherwise, the pending upgrade proposal is removed.
	if err := state.RemovePendingUpgradesForEpoch(ctx, epoch); err != nil {
		return fmt.Errorf("tendermint/governance: couldn't remove pending upgrades for epoch: %w", err)
	}

	return nil
}

func (app *governanceApplication) reclaimProposalDeposit(
	ctx *api.Context,
	stakingState *stakingState.MutableState,
	submitterAddr stakingAPI.Address,
	deposit *quantity.Quantity,
) error {
	submitter, err := stakingState.Account(ctx, submitterAddr)
	if err != nil {
		return fmt.Errorf("failed to fetch account: %w", err)
	}

	deposits, err := stakingState.GovernanceDeposits(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch governance deposits: %w", err)
	}
	if err = quantity.Move(&submitter.General.Balance, deposits, deposit); err != nil {
		ctx.Logger().Error("failed to reclaim governance proposal deposit",
			"err", err,
			"to", submitter.General.Balance,
			"from", deposits,
			"amount", deposit,
		)
		return err
	}

	// Save submitter account.
	if err = stakingState.SetAccount(ctx, submitterAddr, submitter); err != nil {
		ctx.Logger().Error("failed saving submitter account",
			"err", err,
			"address", submitterAddr,
			"account", submitter,
		)
		return fmt.Errorf("failed saving account: %w", err)
	}
	// Save the deposits balance.
	if err = stakingState.SetGovernanceDeposits(ctx, deposits); err != nil {
		ctx.Logger().Error("failed setting governance deposits",
			"err", err,
			"deposits", deposits,
		)
		return fmt.Errorf("failed setting governance deposits: %w", err)
	}

	return nil
}

func (app *governanceApplication) discardProposalDeposit(
	ctx *api.Context,
	stakingState *stakingState.MutableState,
	deposit *quantity.Quantity,
) error {
	commonPool, err := stakingState.CommonPool(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch account: %w", err)
	}

	deposits, err := stakingState.GovernanceDeposits(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch governance deposits: %w", err)
	}
	if err = quantity.Move(commonPool, deposits, deposit); err != nil {
		ctx.Logger().Error("failed to move governance proposal deposit to common pool",
			"err", err,
			"to", commonPool,
			"from", deposits,
			"amount", deposit,
		)
		return err
	}

	// Save the common pool balance.
	if err = stakingState.SetCommonPool(ctx, commonPool); err != nil {
		ctx.Logger().Error("failed setting common pool",
			"err", err,
			"common_pool", commonPool,
		)
		return fmt.Errorf("failed setting common pool: %w", err)
	}

	// Save the deposits balance.
	if err = stakingState.SetGovernanceDeposits(ctx, deposits); err != nil {
		ctx.Logger().Error("failed setting governance deposits",
			"err", err,
			"deposits", deposits,
		)
		return fmt.Errorf("failed setting governance deposits: %w", err)
	}

	return nil
}

func (app *governanceApplication) executeProposal(ctx *api.Context, state *governanceState.MutableState, proposal *governance.Proposal) error {
	switch {
	case proposal.Content.Upgrade != nil:
		// Execute upgrade proposal.
		upgrades, err := state.PendingUpgrades(ctx)
		if err != nil {
			return fmt.Errorf("failed to query upgrades: %w", err)
		}
		if len(upgrades) != 0 {
			return governance.ErrUpgradeAlreadyPending
		}
		err = state.SetPendingUpgrade(ctx, proposal.ID, &proposal.Content.Upgrade.Descriptor)
		if err != nil {
			return fmt.Errorf("failed to set pending upgrade: %w", err)
		}
	case proposal.Content.CancelUpgrade != nil:
		cancelingProposal, err := state.Proposal(ctx, proposal.Content.CancelUpgrade.ProposalID)
		if err != nil {
			return fmt.Errorf("failed to query proposal: %w", err)
		}
		if cancelingProposal.Content.Upgrade != nil {
			return fmt.Errorf("expected canceling proposal to be an upgrade proposal")
		}
		err = state.RemovePendingUpgrade(ctx, cancelingProposal.Content.Upgrade.Epoch, cancelingProposal.ID)
		if err != nil {
			return fmt.Errorf("failed to remove pending upgrade: %w", err)
		}
	default:
		panic("shouldn't ever happen")
	}
	return nil
}

func (app *governanceApplication) validatorsEscrow(
	ctx *api.Context,
	stakingState *stakingState.MutableState,
	registryState *registryState.MutableState,
	schedulerState *schedulerState.MutableState,
) (*quantity.Quantity, map[stakingAPI.Address]*quantity.Quantity, error) {
	currentValidators, err := schedulerState.CurrentValidators(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query current validators: %w", err)
	}

	totalVotingStake := quantity.NewQuantity()
	validatorEntitiesEscrow := make(map[stakingAPI.Address]*quantity.Quantity)
	for valID := range currentValidators {
		var node *node.Node
		node, err = registryState.Node(ctx, valID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to query validator node: %w", err)
		}
		entityAddr := stakingAPI.NewAddress(node.EntityID)

		var escrow *quantity.Quantity
		escrow, err = stakingState.EscrowBalance(ctx, entityAddr)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to query validator escrow: %w", err)
		}

		// If there are multiple nodes in the validator set belonging to the same entity,
		// only count the entity escrow once.
		if validatorEntitiesEscrow[entityAddr] != nil {
			continue
		}
		validatorEntitiesEscrow[entityAddr] = escrow
		if err := totalVotingStake.Add(escrow); err != nil {
			return nil, nil, fmt.Errorf("failed to add to totalVotingStake: %w", err)
		}
	}
	return totalVotingStake, validatorEntitiesEscrow, nil
}

func (app *governanceApplication) closeProposal(
	ctx *api.Context,
	state *governanceState.MutableState,
	totalVotingStake quantity.Quantity,
	validatorEntitiesEscrow map[stakingAPI.Address]*quantity.Quantity,
	proposal *governance.Proposal,
) error {
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch consensus parameters: %w", err)
	}

	proposal.Results = make(map[governance.Vote]quantity.Quantity)
	votes, err := state.Votes(ctx, proposal.ID)
	if err != nil {
		return fmt.Errorf("failed to query votes: %w", err)
	}

	// Tally the votes.
	for _, vote := range votes {
		escrow, ok := validatorEntitiesEscrow[vote.Voter]
		if !ok {
			// Voter not in current validator set - invalid vote.
			proposal.InvalidVotes++
			continue
		}

		currentVotes := proposal.Results[vote.Vote]

		newVotes := escrow.Clone()
		if err := newVotes.Add(&currentVotes); err != nil {
			return fmt.Errorf("failed to add votes: %w", err)
		}
		proposal.Results[vote.Vote] = *newVotes
	}

	if err := proposal.CloseProposal(totalVotingStake, params.Quorum, params.Threshold); err != nil {
		return fmt.Errorf("failed to close proposal: %w", err)
	}

	return nil
}

func (app *governanceApplication) EndBlock(ctx *api.Context, request types.RequestEndBlock) (types.ResponseEndBlock, error) {
	// Check if epoch has changed.
	epochChanged, epoch := app.state.EpochChanged(ctx)
	if !epochChanged {
		// Nothing to do.
		return types.ResponseEndBlock{}, nil
	}

	state := governanceState.NewMutableState(ctx.State())
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return types.ResponseEndBlock{}, fmt.Errorf("failed to fetch consensus parameters: %w", err)
	}

	activeProposals, err := state.ActiveProposals(ctx)
	if err != nil {
		return types.ResponseEndBlock{}, fmt.Errorf("tendermint/governance: couldn't get active proposals: %w", err)
	}
	// Get proposals that are closed this epoch.
	var closingProposals []*governance.Proposal
	for _, proposal := range activeProposals {
		if proposal.ClosesAt != epoch {
			continue
		}
		closingProposals = append(closingProposals, proposal)
	}

	// No proposals closing this epoch.
	if len(closingProposals) == 0 {
		ctx.Logger().Debug("no proposals scheduled to be closed this epoch")
		return types.ResponseEndBlock{}, nil
	}

	ctx.Logger().Debug("proposals scheduled to be closed this epoch",
		"n_proposals", len(closingProposals),
	)

	// Prepare validator set entities state.
	stakingState := stakingState.NewMutableState(ctx.State())
	totalVotingStake, validatorEntitiesEscrow, err := app.validatorsEscrow(
		ctx,
		stakingState,
		registryState.NewMutableState(ctx.State()),
		schedulerState.NewMutableState(ctx.State()),
	)
	if err != nil {
		return types.ResponseEndBlock{}, fmt.Errorf("consensus/governance: failed to compute validators escrow: %w", err)
	}

	for _, proposal := range closingProposals {
		ctx.Logger().Debug("closing proposal",
			"proposal", proposal,
		)

		if err = app.closeProposal(
			ctx,
			state,
			*totalVotingStake,
			validatorEntitiesEscrow,
			proposal,
		); err != nil {
			ctx.Logger().Error("proposal closing failure",
				"err", err,
				"proposal", proposal,
				"params", params,
				"total_voting_stake", totalVotingStake,
				"len_validator_entities_escrow", len(validatorEntitiesEscrow),
			)
			return types.ResponseEndBlock{}, fmt.Errorf("consensus/governance: failed to close a proposal: %w", err)
		}

		ctx.Logger().Debug("proposal closed",
			"proposal", proposal,
			"state", proposal.State,
		)

		// In case the proposal has been passed, the proposal content is executed.
		if proposal.State == governance.StatePassed {
			// Execute.
			if err = app.executeProposal(ctx, state, proposal); err != nil {
				ctx.Logger().Error("proposal execution failure",
					"err", err,
					"proposal", proposal,
				)

				// If proposal execution fails, the proposal's state is changed to StateFailed.
				proposal.State = governance.StateFailed
			} else {
				// If successful, emit Proposal executed event.
				evt := &governance.ProposalExecutedEvent{
					ID: proposal.ID,
				}
				ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyProposalExecuted, cbor.Marshal(evt)))
			}
		}

		// Save the updated proposal.
		if err = state.SetProposal(ctx, proposal); err != nil {
			return types.ResponseEndBlock{}, fmt.Errorf("failed to save proposal: %w", err)
		}
		// Remove proposal from active list.
		if err = state.RemoveActiveProposal(ctx, proposal); err != nil {
			return types.ResponseEndBlock{}, fmt.Errorf("failed to remove active proposal: %w", err)
		}

		// Emit Proposal finalized event.
		evt := &governance.ProposalFinalizedEvent{
			ID:    proposal.ID,
			State: proposal.State,
		}
		ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyProposalFinalized, cbor.Marshal(evt)))

		var transferEvt *stakingAPI.TransferEvent
		switch proposal.State {
		case governance.StatePassed, governance.StateFailed:
			// Transfer back proposal deposits.
			if err = app.reclaimProposalDeposit(
				ctx,
				stakingState,
				proposal.Submitter,
				&proposal.Deposit,
			); err != nil {
				return types.ResponseEndBlock{},
					fmt.Errorf("consensus/governance: failed to reclaim proposal deposit: %w", err)
			}
			transferEvt = &stakingAPI.TransferEvent{
				From:   stakingAPI.GovernanceDepositsAddress,
				To:     proposal.Submitter,
				Amount: params.MinProposalDeposit,
			}

		case governance.StateRejected:
			// Proposal rejected, deposit is transferred into the common pool.
			if err = app.discardProposalDeposit(
				ctx,
				stakingState,
				&proposal.Deposit,
			); err != nil {
				return types.ResponseEndBlock{},
					fmt.Errorf("consensus/governance: failed to reclaim proposal deposit: %w", err)
			}
			transferEvt = &stakingAPI.TransferEvent{
				From:   stakingAPI.GovernanceDepositsAddress,
				To:     stakingAPI.CommonPoolAddress,
				Amount: params.MinProposalDeposit,
			}

		default:
			return types.ResponseEndBlock{},
				fmt.Errorf("consensus/governance: invalid closed proposal state: %v", proposal.State)
		}

		// Proposal deposit transfer.
		ctx.EmitEvent(api.NewEventBuilder(staking.AppName).Attribute(staking.KeyTransfer, cbor.Marshal(transferEvt)))
	}

	return types.ResponseEndBlock{}, nil
}

// New constructs a new governance application instance.
func New() api.Application {
	return &governanceApplication{}
}
