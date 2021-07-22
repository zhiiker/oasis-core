package runtime

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	control "github.com/oasisprotocol/oasis-core/go/control/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	runtimeClient "github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	"github.com/oasisprotocol/oasis-core/go/storage/database"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
)

// StorageSync is the storage sync scenario.
var StorageSync scenario.Scenario = newStorageSyncImpl()

type storageSyncImpl struct {
	runtimeImpl
}

func newStorageSyncImpl() scenario.Scenario {
	return &storageSyncImpl{
		runtimeImpl: *newRuntimeImpl("storage-sync", BasicKVTestClient),
	}
}

func (sc *storageSyncImpl) Clone() scenario.Scenario {
	return &storageSyncImpl{
		runtimeImpl: *sc.runtimeImpl.Clone().(*runtimeImpl),
	}
}

func (sc *storageSyncImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Use mock epochtime to ensure syncing starts in the same epoch in which
	// new node registers.
	f.Network.SetMockEpoch()

	// Enable consensus layer checkpoints.
	f.Network.Consensus.Parameters.StateCheckpointInterval = 10
	f.Network.Consensus.Parameters.StateCheckpointNumKept = 2
	f.Network.Consensus.Parameters.StateCheckpointChunkSize = 1024 * 1024

	// Make the first storage worker check for checkpoints more often.
	f.StorageWorkers[0].CheckpointCheckInterval = 1 * time.Second
	// Configure runtime to allow a smaller replication factor as otherwise execution may fail when
	// the bad node is in the storage committee.
	f.Runtimes[1].Storage.MinWriteReplication = 1
	// Configure runtime for storage checkpointing.
	f.Runtimes[1].Storage.CheckpointInterval = 10
	f.Runtimes[1].Storage.CheckpointNumKept = 1
	f.Runtimes[1].Storage.CheckpointChunkSize = 1 * 1024
	// Provision another storage node and make it ignore all applies.
	f.StorageWorkers = append(f.StorageWorkers, oasis.StorageWorkerFixture{
		Backend:       database.BackendNameBadgerDB,
		Entity:        1,
		IgnoreApplies: true,
	})

	// One more storage worker for later, so it can do an initial sync with the snapshots.
	f.StorageWorkers = append(f.StorageWorkers, oasis.StorageWorkerFixture{
		Backend:                    database.BackendNameBadgerDB,
		Entity:                     1,
		NoAutoStart:                true,
		CheckpointSyncEnabled:      true,
		LogWatcherHandlerFactories: []log.WatcherHandlerFactory{oasis.LogAssertCheckpointSync()},
	})
	// And one more storage worker that will sync the consensus layer via state sync.
	f.StorageWorkers = append(f.StorageWorkers, oasis.StorageWorkerFixture{
		Backend:               database.BackendNameBadgerDB,
		Entity:                1,
		NoAutoStart:           true,
		CheckpointSyncEnabled: true,
		LogWatcherHandlerFactories: []log.WatcherHandlerFactory{
			oasis.LogAssertCheckpointSync(),
			oasis.LogEventABCIStateSyncComplete(),
		},
	})

	return f, nil
}

func (sc *storageSyncImpl) Run(childEnv *env.Env) error { //nolint: gocyclo
	ctx := context.Background()
	if err := sc.startNetworkAndTestClient(ctx, childEnv); err != nil {
		return err
	}

	fixture, err := sc.Fixture()
	if err != nil {
		return err
	}

	if err = sc.initialEpochTransitions(fixture); err != nil {
		return err
	}

	// Wait for the client to exit.
	if err = sc.waitTestClientOnly(); err != nil {
		return err
	}

	drbg, _ := drbgFromSeed([]byte("storage-sync/seq"), []byte("plant_your_seeds"))

	// Check if the storage node that ignored applies has synced.
	sc.Logger.Info("checking if roots have been synced")

	storageNode := sc.Net.StorageWorkers()[2]
	args := []string{
		"debug", "storage", "check-roots",
		"--log.level", "debug",
		"--address", "unix:" + storageNode.SocketPath(),
		sc.Net.Runtimes()[1].ID().String(),
	}
	if err = cli.RunSubCommand(childEnv, sc.Logger, "storage-check-roots", sc.Net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("root check failed after sync: %w", err)
	}

	// Generate some more rounds to trigger checkpointing. Up to this point there have been ~9
	// rounds, we create 15 more rounds to bring this up to ~24. Checkpoints are every 10 rounds so
	// this leaves some space for any unintended epoch transitions.
	for i := 0; i < 15; i++ {
		sc.Logger.Info("submitting transaction to runtime",
			"seq", i,
		)
		if _, err = sc.submitKeyValueRuntimeInsertTx(ctx, runtimeID, "checkpoint", fmt.Sprintf("my cp %d", i), drbg.Uint64()); err != nil {
			return err
		}
	}

	// Make sure that the first storage node created checkpoints.
	ctrl, err := oasis.NewController(sc.Net.StorageWorkers()[0].SocketPath())
	if err != nil {
		return fmt.Errorf("failed to connect with the first storage node: %w", err)
	}

	cps, err := ctrl.Storage.GetCheckpoints(ctx, &checkpoint.GetCheckpointsRequest{Version: 1, Namespace: runtimeID})
	if err != nil {
		return fmt.Errorf("failed to get checkpoints: %w", err)
	}

	blk, err := ctrl.RuntimeClient.GetBlock(ctx, &runtimeClient.GetBlockRequest{
		RuntimeID: runtimeID,
		Round:     runtimeClient.RoundLatest,
	})
	if err != nil {
		return fmt.Errorf("failed to get latest block: %w", err)
	}

	// Determine which checkpoints should be there.
	rt := sc.Net.Runtimes()[1].ToRuntimeDescriptor()
	lastCheckpoint := (blk.Header.Round / rt.Storage.CheckpointInterval) * rt.Storage.CheckpointInterval
	sc.Logger.Info("determined last expected checkpoint round",
		"round", lastCheckpoint,
	)

	// There should be at least two checkpoints. There may be more
	// depending on the state of garbage collection process (which
	// may be one checkpoint behind.)
	if numCps := len(cps); numCps < 2 {
		return fmt.Errorf("incorrect number of checkpoints (expected: >=2 got: %d)", numCps)
	}

	var validCps int
	for checkpoint := rt.Storage.CheckpointInterval; checkpoint <= lastCheckpoint; checkpoint += rt.Storage.CheckpointInterval {
		blk, err = ctrl.RuntimeClient.GetBlock(ctx, &runtimeClient.GetBlockRequest{
			RuntimeID: runtimeID,
			Round:     checkpoint,
		})
		if err != nil {
			return fmt.Errorf("failed to get block %d: %w", checkpoint, err)
		}
		for _, cp := range cps {
			if cp.Root.Version != blk.Header.Round {
				continue
			}
			var found bool
			for _, root := range blk.Header.StorageRoots() {
				if root.Equal(&cp.Root) {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("checkpoint for unexpected root %s", cp.Root)
			}
			sc.Logger.Info("found valid checkpoint",
				"round", checkpoint,
				"root_hash", cp.Root.Hash,
			)
			validCps++
		}
	}
	if validCps < 2 {
		return fmt.Errorf("incorrect number of valid checkpoints (expected: >=2 got: %d)", validCps)
	}

	largeVal := strings.Repeat("has he his auto ", 7) // 16 bytes base string
	for i := 0; i < 32; i++ {
		sc.Logger.Info("submitting large transaction to runtime",
			"seq", i,
		)
		if _, err = sc.submitKeyValueRuntimeInsertTx(ctx, runtimeID, fmt.Sprintf("%d key %d", i, i), fmt.Sprintf("my cp %d: ", i)+largeVal, drbg.Uint64()); err != nil {
			return err
		}
	}

	sc.Logger.Info("running first late storage worker")

	// Now spin up the first late storage worker and check if it syncs with a checkpoint.
	lateWorker := sc.Net.StorageWorkers()[3]
	if err = lateWorker.Start(); err != nil {
		return fmt.Errorf("can't start first late storage worker: %w", err)
	}
	if err = lateWorker.WaitReady(ctx); err != nil {
		return fmt.Errorf("error waiting for first late storage worker to become ready: %w", err)
	}

	sc.Logger.Info("running second late storage worker")

	// Get the TLS public key from the validators.
	var (
		consensusNodes []string
		trustHeight    uint64
		trustHash      string
	)
	for _, v := range sc.Net.Validators() {
		var ctrl *oasis.Controller
		ctrl, err = oasis.NewController(v.SocketPath())
		if err != nil {
			return fmt.Errorf("failed to create controller for validator %s: %w", v.Name, err)
		}

		var status *control.Status
		status, err = ctrl.GetStatus(ctx)
		if err != nil {
			return fmt.Errorf("failed to get status for validator %s: %w", v.Name, err)
		}

		if status.Registration.Descriptor == nil {
			return fmt.Errorf("validator %s has not registered", v.Name)
		}
		if len(status.Registration.Descriptor.TLS.Addresses) == 0 {
			return fmt.Errorf("validator %s has no TLS addresses", v.Name)
		}

		var rawAddress []byte
		tlsAddress := status.Registration.Descriptor.TLS.Addresses[0]
		rawAddress, err = tlsAddress.MarshalText()
		if err != nil {
			return fmt.Errorf("failed to marshal TLS address: %w", err)
		}
		consensusNodes = append(consensusNodes, string(rawAddress))

		trustHeight = uint64(status.Consensus.LatestHeight)
		trustHash = hex.EncodeToString(status.Consensus.LatestHash)
	}

	// Configure state sync for the last storage node.
	lateWorker = sc.Net.StorageWorkers()[4]
	lateWorker.SetConsensusStateSync(&oasis.ConsensusStateSyncCfg{
		ConsensusNodes: consensusNodes,
		TrustHeight:    trustHeight,
		TrustHash:      trustHash,
	})

	if err = lateWorker.Start(); err != nil {
		return fmt.Errorf("can't start second late storage worker: %w", err)
	}
	if err = lateWorker.WaitReady(ctx); err != nil {
		return fmt.Errorf("error waiting for second late storage worker to become ready: %w", err)
	}

	// Wait a bit to give the logger in the node time to sync; the message has already been
	// logged by this point, it just might not be on disk yet.
	<-time.After(1 * time.Second)

	return sc.Net.CheckLogWatchers()
}
