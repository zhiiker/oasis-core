package api

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateBasic(t *testing.T) {
	for _, tc := range []struct {
		msg       string
		p         *ProposalContent
		shouldErr bool
	}{
		{
			msg:       "empty proposal content should fail",
			p:         &ProposalContent{},
			shouldErr: true,
		},
		{
			msg: "only one of Upgrade/CancelUpgrade fields should be set",
			p: &ProposalContent{
				Upgrade:       &UpgradeProposal{},
				CancelUpgrade: &CancelUpgradeProposal{},
			},
			shouldErr: true,
		},
		{
			msg: "upgrade proposal conent should not fail",
			p: &ProposalContent{
				Upgrade: &UpgradeProposal{},
			},
			shouldErr: false,
		},
		{
			msg: "cancel upgrade proposal content should not fail",
			p: &ProposalContent{
				CancelUpgrade: &CancelUpgradeProposal{},
			},
			shouldErr: false,
		},
	} {
		err := tc.p.ValidateBasic()
		if tc.shouldErr {
			require.NotNil(t, err, tc.msg)
			continue
		}
		require.Nil(t, err, tc.msg)
	}
}
