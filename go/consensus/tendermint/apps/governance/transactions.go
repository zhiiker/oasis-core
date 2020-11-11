package governance

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	governanceState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/governance/state"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	schedulerState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/scheduler/state"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	stakingAPI "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func (app *governanceApplication) doProposalDeposit(
	ctx *api.Context,
	stakingState *stakingState.MutableState,
	submitterAddr stakingAPI.Address,
	deposit *quantity.Quantity,
) error {
	submitter, err := stakingState.Account(ctx, submitterAddr)
	if err != nil {
		return fmt.Errorf("failed to fetch account: %w", err)
	}

	// Depsit governance deposits funds.
	deposits, err := stakingState.GovernanceDeposits(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch governance deposits: %w", err)
	}
	if err = quantity.Move(deposits, &submitter.General.Balance, deposit); err != nil {
		ctx.Logger().Error("failed to deposit governance proposal",
			"err", err,
			"from", submitter.General.Balance,
			"to", deposits,
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

func (app *governanceApplication) submitProposal(
	ctx *api.Context,
	state *governanceState.MutableState,
	proposalContent *governance.ProposalContent,
) error {
	if ctx.IsCheckOnly() {
		return nil
	}

	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch consensus parameters: %w", err)
	}

	if err = ctx.Gas().UseGas(1, governance.GasOpSubmitProposal, params.GasCosts); err != nil {
		return err
	}

	// Validate proposal content basics.
	if err = proposalContent.ValidateBasic(); err != nil {
		ctx.Logger().Error("malformed proposal content",
			"content", proposalContent,
			"err", err,
		)
		return governance.ErrInvalidArgument
	}

	// Load submitter account.
	submitterAddr := stakingAPI.NewAddress(ctx.TxSigner())
	if submitterAddr.IsReserved() {
		return stakingAPI.ErrForbidden
	}
	stakingState := stakingState.NewMutableState(ctx.State())
	submitter, err := stakingState.Account(ctx, submitterAddr)
	if err != nil {
		return fmt.Errorf("failed to fetch account: %w", err)
	}

	// Check if submitter has enough balance for proposal deposit.
	if submitter.General.Balance.Cmp(&params.MinProposalDeposit) < 0 {
		ctx.Logger().Error("not enough balance to submit proposal",
			"submitter", submitterAddr,
			"min_proposal_deposit", params.MinProposalDeposit,
		)
		return stakingAPI.ErrInsufficientBalance
	}

	epoch, err := app.state.GetEpoch(ctx, ctx.BlockHeight()+1)
	if err != nil {
		ctx.Logger().Error("failed to get epoch",
			"err", err,
		)
		return err
	}

	switch {
	case proposalContent.Upgrade != nil:
		upgrade := proposalContent.Upgrade
		// TODO: change IsValid() to ValidateBasic().
		if !upgrade.Descriptor.IsValid() {
			ctx.Logger().Error("invalid upgrade descriptor",
				"submitter", submitterAddr,
				"descriptor", upgrade.Descriptor,
			)
			return governance.ErrInvalidArgument
		}

		// Ensure upgrade descriptor epoch is far enough in future.
		if upgrade.Descriptor.Epoch < params.UpgradeMinEpochDiff+epoch {
			ctx.Logger().Error("upgrade descriptor epoch too soon",
				"submitter", submitterAddr,
				"descriptor", upgrade.Descriptor,
				"upgrade_min_epoch_diff", params.UpgradeMinEpochDiff,
				"current_epoch", epoch,
			)
			return governance.ErrUpgradeTooSoon
		}
	case proposalContent.CancelUpgrade != nil:
		cancelUpgrade := proposalContent.CancelUpgrade
		// Check if the cancelation upgrade exists.
		var upgrade *governance.UpgradeProposal
		upgrade, err = state.PendingUpgradeProposal(ctx, cancelUpgrade.ProposalID)
		switch err {
		case nil:
		case governance.ErrNoSuchUpgrade:
			ctx.Logger().Error("cancel upgrade for a non existing upgrade proposal",
				"proposal_id", cancelUpgrade.ProposalID,
				"err", err,
			)
			return err
		default:
			ctx.Logger().Error("error loading proposal",
				"proposal_id", cancelUpgrade.ProposalID,
				"err", err,
			)
			return err
		}

		// Ensure upgrade descriptor is far enough in future so that cancelation is still allowed.
		if upgrade.Descriptor.Epoch < params.UpgradeCancelMinEpochDiff+epoch {
			return governance.ErrUpgradeTooSoon
		}
	}

	// Deposit proposal funds.
	if err = app.doProposalDeposit(
		ctx,
		stakingState,
		submitterAddr,
		&params.MinProposalDeposit,
	); err != nil {
		return fmt.Errorf("failed to deposit governance: %w", err)
	}

	// Load the next proposal identifier.
	id, err := state.NextProposalIdentifier(ctx)
	if err != nil {
		ctx.Logger().Error("failed to get next proposal identifier",
			"err", err,
		)
		return fmt.Errorf("failed to get next proposal identifier: %w", err)
	}
	if err := state.SetNextProposalIdentifier(ctx, id+1); err != nil {
		ctx.Logger().Error("failed to set next proposal identifier",
			"err", err,
		)
		return fmt.Errorf("failed to set next proposal identifier: %w", err)
	}
	// Create the proposal.
	proposal := &governance.Proposal{
		ID:        id,
		ClosesAt:  epoch + params.VotingPeriod,
		Content:   *proposalContent,
		CreatedAt: epoch,
		Deposit:   params.MinProposalDeposit,
		State:     governance.StateActive,
		Submitter: submitterAddr,
	}
	if err := state.SetActiveProposal(ctx, proposal); err != nil {
		ctx.Logger().Error("failed to set active proposal",
			"err", err,
		)
		return fmt.Errorf("failed to set active proposal: %w", err)
	}

	// Emit events.
	// Proposal submitted.
	evt := &governance.ProposalSubmittedEvent{
		ID:        proposal.ID,
		Submitter: proposal.Submitter,
	}
	ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyProposalSubmitted, cbor.Marshal(evt)))

	// Transfer from the submitted to the proposal deposit account.
	transferEvt := &stakingAPI.TransferEvent{
		From:   submitterAddr,
		To:     stakingAPI.GovernanceDepositsAddress,
		Amount: params.MinProposalDeposit,
	}
	ctx.EmitEvent(api.NewEventBuilder(staking.AppName).Attribute(staking.KeyTransfer, cbor.Marshal(transferEvt)))

	return nil
}

func (app *governanceApplication) castVote(
	ctx *api.Context,
	state *governanceState.MutableState,
	proposalVote *governance.ProposalVote,
) error {
	if ctx.IsCheckOnly() {
		return nil
	}

	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch consensus parameters: %w", err)
	}

	if err = ctx.Gas().UseGas(1, governance.GasOpCastVote, params.GasCosts); err != nil {
		return err
	}

	submitterAddr := stakingAPI.NewAddress(ctx.TxSigner())
	if submitterAddr.IsReserved() {
		return stakingAPI.ErrForbidden
	}

	// Query signer entity descriptor.
	registryState := registryState.NewMutableState(ctx.State())
	submitterEntity, err := registryState.Entity(ctx, ctx.TxSigner())
	if err != nil {
		return err
	}
	schedulerState := schedulerState.NewMutableState(ctx.State())
	currentValidators, err := schedulerState.CurrentValidators(ctx)
	if err != nil {
		return fmt.Errorf("failed to query current validators: %w", err)
	}
	// Submitter is eligible if any of its nodes is part of the current validator committee.
	var eligible bool
	for _, nID := range submitterEntity.Nodes {
		if _, ok := currentValidators[nID]; ok {
			eligible = true
			break
		}
	}
	if !eligible {
		ctx.Logger().Error("submitter not eligible to vote",
			"submitter", ctx.TxSigner(),
		)
		return governance.ErrNotEligible
	}

	// Load proposal.
	proposal, err := state.Proposal(ctx, proposalVote.ID)
	switch err {
	case nil:
	case governance.ErrNoSuchProposal:
		ctx.Logger().Error("vote for a missing proposal",
			"proposal_id", proposalVote.ID,
		)
		return governance.ErrNoSuchProposal
	default:
		ctx.Logger().Error("error loading proposal",
			"err", err,
			"proposal_id", proposalVote.ID,
		)
	}
	// Ensure proposal is active.
	if proposal.State != governance.StateActive {
		ctx.Logger().Error("vote for a non-active proposal",
			"proposal_id", proposalVote.ID,
			"state", proposal.State,
			"proposal", proposal,
			"vote", proposalVote,
		)
		return governance.ErrVotingIsClosed
	}

	// Save the vote.
	if err := state.SetVote(ctx, proposal.ID, submitterAddr, proposalVote.Vote); err != nil {
		return fmt.Errorf("failed to save the vote: %w", err)
	}

	// Emit event.
	evt := &governance.VoteEvent{
		ID:        proposal.ID,
		Submitter: proposal.Submitter,
		Vote:      proposalVote.Vote,
	}
	ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyVote, cbor.Marshal(evt)))

	return nil
}
