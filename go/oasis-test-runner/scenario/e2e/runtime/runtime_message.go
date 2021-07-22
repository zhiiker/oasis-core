package runtime

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

var (
	// RuntimeMessage is the runtime message scenario.
	RuntimeMessage scenario.Scenario = newRuntimeMessage()

	waitTimeout = 10 * time.Second
)

type runtimeMessageImpl struct {
	runtimeImpl
}

func newRuntimeMessage() scenario.Scenario {
	return &runtimeMessageImpl{
		runtimeImpl: *newRuntimeImpl("runtime-message", nil),
	}
}

func (sc *runtimeMessageImpl) Clone() scenario.Scenario {
	return &runtimeMessageImpl{
		runtimeImpl: *sc.runtimeImpl.Clone().(*runtimeImpl),
	}
}

func (sc *runtimeMessageImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}
	// Use mock epoch to ensure no rounds due to epoch transition. This way we
	// test batch proposals when there are no transactions but message results.
	f.Network.SetMockEpoch()
	return f, nil
}

func (sc *runtimeMessageImpl) Run(childEnv *env.Env) error {
	if err := sc.Net.Start(); err != nil {
		return err
	}

	fixture, err := sc.Fixture()
	if err != nil {
		return err
	}

	if err = sc.initialEpochTransitions(fixture); err != nil {
		return err
	}

	ctx := context.Background()
	c := sc.Net.ClientController().RuntimeClient

	// We should be at round 2 after the epoch transitions, plus 1 for the genesis block.
	waitCtx, cancel := context.WithTimeout(ctx, waitTimeout)
	defer cancel()
	if err = c.WaitBlockIndexed(waitCtx, &api.WaitBlockIndexedRequest{RuntimeID: runtimeID, Round: 3}); err != nil {
		return err
	}

	// Save latest round.
	sc.Logger.Debug("querying latest round")
	round, err := c.GetBlock(ctx, &api.GetBlockRequest{RuntimeID: runtimeID, Round: api.RoundLatest})
	if err != nil {
		return err
	}
	latestRound := round.Header.Round
	sc.Logger.Debug("latest runtime round", "round", latestRound)
	if latestRound != 3 {
		return fmt.Errorf("unexpected latest round, got: %d, expected: %d", latestRound, 3)
	}

	blkCh, sub, err := c.WatchBlocks(ctx, runtimeID)
	if err != nil {
		return err
	}
	defer sub.Close()

	// Submit a consensus transfer transaction. This should result in two runtime
	// rounds:
	//   - in first round the consensus transfer transaction should be executed
	//   - in the second round there should be no transactions, the round should
	//     contain message results of the consensus transfer.
	sc.Logger.Debug("submitting consensus_transfer runtime transaction")
	if err = sc.submitConsensusXferTx(ctx, runtimeID, staking.Transfer{}, 0); err != nil {
		return err
	}

	sc.Logger.Debug("watching runtime round transitions")
	var reachedMsgRound bool
	for {
		select {
		case blk := <-blkCh:
			round := blk.Block.Header.Round
			sc.Logger.Debug("round transition", "round", round, "header", blk.Block.Header)
			switch {
			case round <= latestRound:
				// Skip old rounds.
				continue
			case round > latestRound+2:
				// Only two rounds are expected.
				return fmt.Errorf("unexpected runtime round: %d", round)
			default:
				if ht := blk.Block.Header.HeaderType; ht != block.Normal {
					return fmt.Errorf("expected normal round, got: %d", ht)
				}
				txs, err := c.GetTxs(ctx, &api.GetTxsRequest{
					RuntimeID: runtimeID,
					Round:     round,
					IORoot:    blk.Block.Header.IORoot,
				})
				if err != nil {
					return err
				}
				switch round {
				case latestRound + 1:
					// Round with the submitted consensus_transfer transaction.
					if len(txs) != 1 {
						return fmt.Errorf("expected 1 transaction at round: %d, got: %d", round, len(txs))
					}
				case latestRound + 2:
					// Round with no transactions - triggered due to message results.
					if len(txs) != 0 {
						return fmt.Errorf("expected 0 transactions at round: %d, got: %d", round, len(txs))
					}
					reachedMsgRound = true
				}
			}
		case <-time.After(waitTimeout):
			if !reachedMsgRound {
				return fmt.Errorf("timed out waiting for runtime rounds")
			}
			return nil
		}
	}
}
