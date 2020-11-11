package api

import (
	"fmt"

	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
)

// SanityCheck performs a sanity check on the consensus parameters.
func (p *ConsensusParameters) SanityCheck() error {
	// TODO:
	return nil
}

// SanityCheckProposals sanity checks proposals.
func SanityCheckProposals() error {
	// TODO:
	return nil
}

// SanityCheck does basic sanity checking on the genesis state.
func (g *Genesis) SanityCheck(now epochtime.EpochTime) error {
	if err := g.Parameters.SanityCheck(); err != nil {
		return fmt.Errorf("governance: sanity check failed: %w", err)
	}
	return nil
}
