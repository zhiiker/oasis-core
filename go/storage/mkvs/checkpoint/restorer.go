package checkpoint

import (
	"context"
	"errors"
	"io"
	"sync"

	db "github.com/oasislabs/oasis-core/go/storage/mkvs/db/api"
)

// restorer is a checkpoint restorer.
type restorer struct {
	sync.Mutex

	ndb db.NodeDB

	// currentCheckpoint contains the metadata of the checkpoint that is currently being restored.
	// If it is nil then no restore is in progress.
	currentCheckpoint *Metadata
	// pendingChunks is a set of pending chunks.
	pendingChunks map[uint64]bool
}

// Implements Restorer.
func (rs *restorer) StartRestore(ctx context.Context, checkpoint *Metadata) error {
	rs.Lock()
	defer rs.Unlock()

	if rs.currentCheckpoint != nil {
		return ErrRestoreAlreadyInProgress
	}

	rs.currentCheckpoint = checkpoint
	rs.pendingChunks = make(map[uint64]bool)
	for idx := range checkpoint.Chunks {
		rs.pendingChunks[uint64(idx)] = true
	}

	return nil
}

// Implements Restorer.
func (rs *restorer) RestoreChunk(ctx context.Context, idx uint64, r io.Reader) (bool, error) {
	chunk, err := func() (*ChunkMetadata, error) {
		rs.Lock()
		defer rs.Unlock()

		if rs.currentCheckpoint == nil {
			return nil, ErrNoRestoreInProgress
		}

		// Check if the given chunk is still pending.
		if !rs.pendingChunks[idx] {
			return nil, ErrChunkAlreadyRestored
		}

		return rs.currentCheckpoint.GetChunkMetadata(idx)
	}()
	if err != nil {
		return false, err
	}

	err = restoreChunk(ctx, rs.ndb, chunk, r)
	switch {
	case err == nil:
	case errors.Is(err, ErrChunkProofVerificationFailed):
		// Chunk was as specified in the manifest but did not match the reported root. In this case
		// we need to abort processing the given checkpoint.
		rs.Lock()
		defer rs.Unlock()

		rs.pendingChunks = nil
		rs.currentCheckpoint = nil

		return false, err
	default:
		return false, err
	}

	rs.Lock()
	defer rs.Unlock()

	// Mark the given chunk as restored.
	delete(rs.pendingChunks, idx)

	// If there are no more pending chunks, restore is done.
	if len(rs.pendingChunks) == 0 {
		rs.pendingChunks = nil
		rs.currentCheckpoint = nil

		return true, nil
	}

	return false, nil
}

// NewRestorer creates a new checkpoint restorer.
func NewRestorer(ndb db.NodeDB) (Restorer, error) {
	return &restorer{ndb: ndb}, nil
}