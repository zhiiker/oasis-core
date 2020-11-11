package governance

import (
	"context"
	"fmt"

	"github.com/tendermint/tendermint/abci/types"

	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	governanceState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/governance/state"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
)

func (app *governanceApplication) InitChain(ctx *abciAPI.Context, request types.RequestInitChain, doc *genesis.Document) error {
	st := doc.Governance

	// TODO: check if this returns correct epoch?
	epoch, err := app.state.GetEpoch(ctx, ctx.BlockHeight()+1)
	if err != nil {
		ctx.Logger().Error("failed to get epoch",
			"err", err,
		)
		return err
	}

	state := governanceState.NewMutableState(ctx.State())
	if err := state.SetConsensusParameters(ctx, &st.Parameters); err != nil {
		return fmt.Errorf("failed to set consensus parameters: %w", err)
	}

	if err := state.SetNextProposalIdentifier(ctx, st.NextProposalIdentifier); err != nil {
		return fmt.Errorf("failed to set next proposal identifier: %w", err)
	}

	// Insert proposals.
	for _, proposal := range st.Proposals {
		switch proposal.State {
		case governance.StateActive:
			if err := state.SetActiveProposal(ctx, proposal); err != nil {
				return fmt.Errorf("failed to set active proposal: %w", err)
			}
		default:
			if err := state.SetProposal(ctx, proposal); err != nil {
				return fmt.Errorf("failed to set consensus parameters: %w", err)
			}
		}
		// Insert votes for the proposal.
		for _, vote := range st.VoteEntries[proposal.ID] {
			if err := state.SetVote(ctx, proposal.ID, vote.Voter, vote.Vote); err != nil {
				return fmt.Errorf("failed to set vote: %w", err)
			}
		}

		// Unless this is a passed upgrade proposal, there's nothing left to do.
		if proposal.State != governance.StatePassed || proposal.Content.Upgrade == nil {
			continue
		}

		// If the upgrade is for an old  epoch, skip it as it isn't relevant anymore.
		if proposal.Content.Upgrade.Epoch < epoch {
			continue
		}

		// Set the pending upgrade.
		if err := state.SetPendingUpgrade(ctx, proposal.ID, &proposal.Content.Upgrade.Descriptor); err != nil {
			return fmt.Errorf("failed to set pending upgrade :%w", err)
		}
	}

	return nil
}

// Genesis exports current state in genesis format.
func (gq *governanceQuerier) Genesis(ctx context.Context) (*governance.Genesis, error) {
	params, err := gq.state.ConsensusParameters(ctx)
	if err != nil {
		return nil, err
	}

	nextID, err := gq.state.NextProposalIdentifier(ctx)
	if err != nil {
		return nil, err
	}

	proposals, err := gq.state.Proposals(ctx)
	if err != nil {
		return nil, err
	}

	voteEntries := make(map[uint64][]*governance.VoteEntry)
	for _, proposal := range proposals {
		var votes []*governance.VoteEntry
		votes, err = gq.state.Votes(ctx, proposal.ID)
		if err != nil {
			return nil, err
		}
		voteEntries[proposal.ID] = votes
	}

	genesis := &governance.Genesis{
		Parameters:             *params,
		NextProposalIdentifier: nextID,
		Proposals:              proposals,
		VoteEntries:            voteEntries,
	}
	return genesis, nil
}
