// Package api implements the governance APIs.
package api

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

// ModuleName is a unique module name for the governance backend.
const ModuleName = "governance"

var (
	// ErrInvalidArgument is the error returned on malformed argument(s).
	ErrInvalidArgument = errors.New(ModuleName, 1, "governance: invalid argument")
	// ErrUpgradeTooSoon is the error returned when an upgrade is not enough in the future.
	ErrUpgradeTooSoon = errors.New(ModuleName, 2, "governance: upgrade too soon")
	// ErrUpgradeAlreadyPending is the error returned when an upgrade is already pending.
	ErrUpgradeAlreadyPending = errors.New(ModuleName, 3, "governance: upgrade already pending")
	// ErrNoSuchUpgrade is the error returned when an upgrade does not exist.
	ErrNoSuchUpgrade = errors.New(ModuleName, 4, "governance: no such upgrade")
	// ErrNoSuchProposal is the error retrued when a proposal does not exist.
	ErrNoSuchProposal = errors.New(ModuleName, 5, "governance: no such proposal")
	// ErrNotEligible is the error returned when a vote caster is not eligible for a vote.
	ErrNotEligible = errors.New(ModuleName, 6, "governance: not eligible")
	// ErrVotingIsClosed is the error returned when a vote is cast for a non-active proposal.
	ErrVotingIsClosed = errors.New(ModuleName, 7, "governance: voting is closed")

	// SubmitProposal submits a new consensus layer governance proposal.
	SubmitProposal = transaction.NewMethodName(ModuleName, "SubmitProposal", ProposalContent{})
	// CastVote casts a vote for a consensus layer governance proposal.
	CastVote = transaction.NewMethodName(ModuleName, "CastVote", ProposalVote{})

	// Methods is the list of all methods supported by the governance backend.
	Methods = []transaction.MethodName{
		SubmitProposal,
		CastVote,
	}
)

// ProposalContent is a consensus layer governance proposal content.
type ProposalContent struct {
	Upgrade       *UpgradeProposal       `json:"upgrade,omitempty"`
	CancelUpgrade *CancelUpgradeProposal `json:"cancel_upgrade,omitempty"`
}

// ValidateBasic performs basic proposal content validity checks.
//
// Note that this doesn't check validity of inner fields.
func (p *ProposalContent) ValidateBasic() error {
	switch {
	case p.Upgrade == nil && p.CancelUpgrade == nil,
		p.Upgrade != nil && p.CancelUpgrade != nil:
		return fmt.Errorf("exactly one of the: `Upgrade` or `CancelUpgrade` fields need to be set at the time")
	default:
	}
	return nil
}

// UpgradeProposal is an upgrade proposal.
type UpgradeProposal struct {
	upgrade.Descriptor
}

// CancelUpgradeProposal is an upgrade cancellation proposal.
type CancelUpgradeProposal struct {
	// ProposalID is the identifier of the pending upgrade proposal.
	ProposalID uint64 `json:"proposal_id"`
}

// ProposalVote is a vote for a proposal.
type ProposalVote struct {
	// ID is the unique identifier of a proposal.
	ID uint64 `json:"id"`
	// Vote is the vote.
	Vote Vote `json:"vote"`
}

// Backend is a governance implementation.
type Backend interface {
	// ActiveProposals returns a list of all proposals that have not yet closed.
	ActiveProposals(ctx context.Context, height int64) ([]*Proposal, error)
	// Proposal looks up a specific proposal.
	Proposal(ctx context.Context, query *ProposalQuery) (*Proposal, error)
	// Votes looks up votes for a specific proposal.
	Votes(ctx context.Context, query *ProposalQuery) ([]*VoteEntry, error)
	// PendingUpgrades returns a list of all pending upgrades.
	PendingUpgrades(ctx context.Context, height int64) ([]*upgrade.Descriptor, error)
}

// ProposalQuery is a proposal query.
type ProposalQuery struct {
	Height int64  `json:"height"`
	ID     uint64 `json:"id"`
}

// VoteEntry contains data about a cast vote.
type VoteEntry struct {
	Voter staking.Address `json:"voter"`
	Vote  Vote            `json:"vote"`
}

// Genesis is the initial governance state for use in the genesis block.
type Genesis struct {
	// Parameters are the genesis consensus parameters.
	Parameters ConsensusParameters `json:"params"`

	// NextProposalIdentifier is the identifier used for next new proposal.
	NextProposalIdentifier uint64 `json:"next_proposal_identifier,omitempty"`

	// Proposals are the governance proposals.
	Proposals []*Proposal `json:"proposals,omitempty"`

	// VoteEntries are the governance proposal vote entries.
	VoteEntries map[uint64][]*VoteEntry `json:"vote_entries,omitempty"`
}

// ConsensusParameters are the governance consensus parameters.
type ConsensusParameters struct {
	// GasCosts are the governance transaction gas costs.
	GasCosts transaction.Costs `json:"gas_costs,omitempty"`

	// MinProposalDeposit is the number of base units that are deposited when
	// creating a new proposal.
	MinProposalDeposit quantity.Quantity `json:"min_proposal_deposit,omitempty"`

	// VotingPeriod is the number of epochs after which the voting for a proposal
	// is closed and the votes are tallied.
	VotingPeriod epochtime.EpochTime `json:"voting_period,omitempty"`

	// Quorum is he minimum percentage of voting power that needs to be cast on
	// a proposal for the result to be valid.
	Quorum uint8 `json:"quorum,omitempty"`

	// Threshold is the minimum percentage of VoteYes votes in order for a
	// proposal to be accepted.
	Threshold uint8 `json:"threshold,omitempty"`

	// UpgradeMinEpochDiff is the minimum number of epochs between the current
	// epoch and the proposed upgrade epoch for the upgrade proposal to be valid.
	UpgradeMinEpochDiff epochtime.EpochTime `json:"upgrade_min_epoch_diff,omitempty"`

	// UpgradeCancelMinEpochDiff is the minimum number of epochs between the current
	// epoch and the proposed upgrade epoch for the upgrade cancellation proposal to be valid.
	UpgradeCancelMinEpochDiff epochtime.EpochTime `json:"upgrade_cancel_min_epoch_diff,omitempty"`
}

// ProposalSubmittedEvent is the event emitted when a new proposal is submitted.
type ProposalSubmittedEvent struct {
	// ID is the unique identifier of a proposal.
	ID uint64 `json:"id"`
	// Submitter is the staking account address of the submitter.
	Submitter staking.Address `json:"submitter"`
}

// ProposalExecutedEvent is emitted when a proposal is executed.
type ProposalExecutedEvent struct {
	// ID is the unique identifier of a proposal.
	ID uint64 `json:"id"`
}

// ProposalFinalizedEvent is the event emitted when a proposal is finalized.
type ProposalFinalizedEvent struct {
	// ID is the unique identifier of a proposal.
	ID uint64 `json:"id"`
	// State is the new proposal state.
	State ProposalState `json:"state"`
}

// VoteEvent is the event emitted when a vote is cast.
type VoteEvent struct {
	// ID is the unique identifier of a proposal.
	ID uint64 `json:"id"`
	// Submitter is the staking account address of the submitter.
	Submitter staking.Address `json:"submitter"`
	// Vote is the cast vote.
	Vote Vote `json:"vote"`
}

const (
	// GasOpSubmitProposal is the gas operation identifier for submitting proposal.
	GasOpSubmitProposal transaction.Op = "submit_proposal"
	// GasOpCastVote is the gas operation identifier for casting vote.
	GasOpCastVote transaction.Op = "cast_vote"
)

// DefaultGasCosts are the "default" gas costs for operations.
var DefaultGasCosts = transaction.Costs{
	GasOpSubmitProposal: 1000,
	GasOpCastVote:       1000,
}
