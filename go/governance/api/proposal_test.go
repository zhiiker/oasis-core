package api

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/quantity"
)

func TestVotedSum(t *testing.T) {
	for _, tc := range []struct {
		msg      string
		p        *Proposal
		expected *quantity.Quantity
	}{
		{
			msg:      "empty results should be 0",
			p:        &Proposal{},
			expected: quantity.NewFromUint64(0),
		},
		{
			msg: "results sum should match",
			p: &Proposal{
				Results: map[Vote]quantity.Quantity{
					VoteNo:      *quantity.NewFromUint64(1),
					VoteYes:     *quantity.NewFromUint64(7),
					VoteAbstain: *quantity.NewFromUint64(13),
				},
			},
			expected: quantity.NewFromUint64(21),
		},
	} {
		res, err := tc.p.VotedSum()
		require.NoError(t, err, tc.msg)
		require.EqualValues(t, 0, res.Cmp(tc.expected))
	}
}

func TestCloseProposal(t *testing.T) {
	totalVotingStake := quantity.NewFromUint64(100)
	for _, tc := range []struct {
		msg string

		p                *Proposal
		totalVotingStake *quantity.Quantity
		quorum           uint8
		threshold        uint8

		expectedState ProposalState
		expectedErr   error
	}{
		{
			msg: "proposal in invalid state",
			p: &Proposal{
				State: StateFailed,
			},
			totalVotingStake: totalVotingStake,
			expectedErr:      errInvalidProposalState,
		},
		{
			msg: "proposal without results",
			p: &Proposal{
				State: StateActive,
			},
			totalVotingStake: totalVotingStake,
			expectedErr:      errInvalidProposalState,
		},
		{
			msg: "proposal quotum not reached",
			p: &Proposal{
				State: StateActive,
				Results: map[Vote]quantity.Quantity{
					// 100% of votes Yes, but quorum is only 80%.
					VoteYes: *quantity.NewFromUint64(80),
				},
			},
			totalVotingStake: totalVotingStake,
			quorum:           90,
			threshold:        90,
			expectedState:    StateRejected,
		},
		{
			msg: "proposal threshold not reached",
			p: &Proposal{
				State: StateActive,
				// Quorum reached, but threshold not reached.
				Results: map[Vote]quantity.Quantity{
					VoteYes:     *quantity.NewFromUint64(55),
					VoteNo:      *quantity.NewFromUint64(40),
					VoteAbstain: *quantity.NewFromUint64(1),
				},
			},
			totalVotingStake: totalVotingStake,
			quorum:           90,
			threshold:        90,
			expectedState:    StateRejected,
		},
		{
			msg: "more votes than possible",
			p: &Proposal{
				State: StateActive,
				Results: map[Vote]quantity.Quantity{
					VoteYes: *quantity.NewFromUint64(200),
				},
			},
			totalVotingStake: totalVotingStake,
			expectedErr:      errInvalidProposalState,
		},
		{
			msg: "proposal of all Vote yes should pass",
			p: &Proposal{
				State: StateActive,
				Results: map[Vote]quantity.Quantity{
					VoteYes: *quantity.NewFromUint64(100),
				},
			},
			totalVotingStake: totalVotingStake,
			quorum:           90,
			threshold:        90,
			expectedState:    StatePassed,
		},
		{
			msg: "proposal should pass",
			p: &Proposal{
				State: StateActive,
				// Quorum and threshold reached.
				// Quorum: 91/100: 91%
				// Threshold: 85/91: ~93%
				Results: map[Vote]quantity.Quantity{
					VoteYes:     *quantity.NewFromUint64(85),
					VoteNo:      *quantity.NewFromUint64(3),
					VoteAbstain: *quantity.NewFromUint64(3),
				},
			},
			totalVotingStake: totalVotingStake,
			quorum:           90,
			threshold:        90,
			expectedState:    StatePassed,
		},
	} {
		err := tc.p.CloseProposal(*tc.totalVotingStake, tc.quorum, tc.threshold)
		if tc.expectedErr != nil {
			require.True(t, errors.Is(err, tc.expectedErr),
				fmt.Sprintf("expected error: %v, got: %v: for case: %s", tc.expectedErr, err, tc.msg))
			continue
		}
		require.Equal(t, tc.expectedState, tc.p.State, tc.msg)
	}
}
