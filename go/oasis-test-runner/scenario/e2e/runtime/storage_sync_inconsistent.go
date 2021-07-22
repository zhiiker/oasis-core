package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/storage/database"
)

const checkpointInterval = 5

// StorageSyncInconsistent is the inconsistent storage sync scenario.
var StorageSyncInconsistent scenario.Scenario = newStorageSyncInconsistentImpl()

type storageSyncInconsistentImpl struct {
	runtimeImpl
	messyStorage int
	runtimeID    common.Namespace
}

func newStorageSyncInconsistentImpl() scenario.Scenario {
	return &storageSyncInconsistentImpl{
		runtimeImpl: *newRuntimeImpl(
			"storage-sync-inconsistent",
			NewKeyValueTestClient().WithRepeat(),
		),
	}
}

func (sc *storageSyncInconsistentImpl) Clone() scenario.Scenario {
	return &storageSyncInconsistentImpl{
		runtimeImpl: *sc.runtimeImpl.Clone().(*runtimeImpl),
	}
}

func (sc *storageSyncInconsistentImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Use mock epochtime to ensure syncing starts in the same epoch in which
	// new node registers.
	f.Network.SetMockEpoch()

	f.Runtimes[1].Storage.CheckpointInterval = checkpointInterval
	f.Runtimes[1].Storage.CheckpointNumKept = 100

	f.StorageWorkers = append(f.StorageWorkers, f.StorageWorkers[0])
	f.StorageWorkers[0].CheckpointCheckInterval = 1 * time.Second

	// One more storage worker for later, this is the one we'll be messing with.
	f.StorageWorkers = append(f.StorageWorkers, oasis.StorageWorkerFixture{
		Backend:               database.BackendNameBadgerDB,
		Entity:                1,
		NoAutoStart:           false,
		CheckpointSyncEnabled: true,
	})
	sc.messyStorage = len(f.StorageWorkers) - 1

	return f, nil
}

func (sc *storageSyncInconsistentImpl) waitForSegment(ctx context.Context, worker *oasis.Storage, seg, offset int) error {
	round := uint64(seg*checkpointInterval + offset)
	sc.Logger.Info("waiting for round", "round", round)
	waitedRound, err := worker.WaitForRound(ctx, sc.runtimeID, round)
	if err != nil {
		return fmt.Errorf("error waiting for round %d: %w", round, err)
	}
	if waitedRound > round {
		return fmt.Errorf("storage worker was already ahead (at round %d instead of %d), increase the checkpointing interval",
			waitedRound,
			round,
		)
	}
	return nil
}

func (sc *storageSyncInconsistentImpl) wipe(ctx context.Context, worker *oasis.Node) error {
	return os.RemoveAll(persistent.GetPersistentStoreDBDir(worker.DataDir()))
}

func (sc *storageSyncInconsistentImpl) Run(childEnv *env.Env) error {
	storage0 := sc.Net.StorageWorkers()[0]
	messyWorker := sc.Net.StorageWorkers()[sc.messyStorage]
	sc.runtimeID = sc.Net.Runtimes()[1].ID()
	ctx := context.Background()

	if err := sc.runtimeImpl.startNetworkAndTestClient(ctx, childEnv); err != nil {
		return err
	}

	fixture, err := sc.Fixture()
	if err != nil {
		return err
	}

	if err = sc.initialEpochTransitions(fixture); err != nil {
		return err
	}

	// Kill the messy worker just before the first checkpoint is due.
	if err = sc.waitForSegment(ctx, storage0, 1, 2); err != nil {
		return err
	}

	sc.Logger.Info("pausing checkpointers in all storage workers")
	for _, worker := range sc.Net.StorageWorkers() {
		if worker == messyWorker {
			continue
		}
		if err = worker.PauseCheckpointer(ctx, sc.runtimeID, true); err != nil {
			return err
		}
	}

	// The expected failure situation here is as follows:
	// - the newly started node has a wiped persistent state and thus won't be aware
	//   of what it's already synced, meaning it'll try syncing everything
	// - when trying to sync checkpoints, these should all fail; aborting didn't use to
	//   work properly, meaning that when the syncer exited, the database was still in
	//   multipart restore mode
	// - if any new checkpoints become available while the syncer is still trying to run,
	//   then those will succeed (because they'll be for rounds that don't exist yet locally
	//   in the messy worker), breaking the test
	// - when the checkpoint syncer exits (leaving behind an inconsistent db), the regular
	//   round syncing logic won't be able to proceed because no apply operations will
	//   succeed
	//
	// The test needs to ensure that when the messy worker is restarted, there will
	// be checkpoints available but all need to fail (easiest is if they've been already
	// synced) *and* no new checkpoints are generated until the checkpointer exits.

	sc.Logger.Info("stopping and wiping messy storage worker")
	if err = messyWorker.Stop(); err != nil {
		return err
	}
	if err = sc.wipe(ctx, messyWorker.Node); err != nil {
		return err
	}

	if err = messyWorker.Start(); err != nil {
		return err
	}
	if err = messyWorker.WaitReady(ctx); err != nil {
		return err
	}

	// Wait for the client to exit. Odd error handling here; if killing succeeded, then everything
	// must have been fine up to this point and we can ignore the exit error from the kill.
	sc.Logger.Info("scenario done, killing client")
	testClient := sc.testClient.(*KeyValueTestClient)
	if err = testClient.Kill(); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
	}

	// No need to wait, client is dead at this point.  Unfortunately
	// the error didn't indicate cancelation though.

	return sc.Net.CheckLogWatchers()
}
