// Package checkpoint provides methods for creating MKVS checkpoints.
package checkpoint

import (
	"context"
	"io"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/errors"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/node"
)

const moduleName = "storage/mkvs/checkpoint"

var (
	// ErrCheckpointNotFound is the error when a checkpoint is not found.
	ErrCheckpointNotFound = errors.New(moduleName, 1, "checkpoint: not found")

	// ErrChunkNotFound is the error when a chunk is not found.
	ErrChunkNotFound = errors.New(moduleName, 2, "checkpoint: chunk not found")

	// ErrRestoreAlreadyInProgress is the error when a checkpoint restore is already in progress and
	// the caller wanted to start another restore.
	ErrRestoreAlreadyInProgress = errors.New(moduleName, 3, "checkpoint: restore already in progress")

	// ErrNoRestoreInProgress is the error when no checkpoint restore is currently in progress.
	ErrNoRestoreInProgress = errors.New(moduleName, 4, "checkpoint: no restore in progress")

	// ErrChunkAlreadyRestored is the error when a chunk has already been restored.
	ErrChunkAlreadyRestored = errors.New(moduleName, 5, "checkpoint: chunk already restored")

	// ErrChunkProofVerificationFailed is the error when a chunk fails proof verification.
	ErrChunkProofVerificationFailed = errors.New(moduleName, 6, "chunk: chunk proof verification failed")

	// ErrChunkCorrupted is the error when a chunk is corrupted.
	ErrChunkCorrupted = errors.New(moduleName, 7, "chunk: corrupted chunk")
)

// ChunkProvider is a chunk provider.
type ChunkProvider interface {
	// GetCheckpoints returns a list of checkpoint metadata for all known checkpoints.
	GetCheckpoints(ctx context.Context, request *GetCheckpointsRequest) ([]*Metadata, error)

	// GetCheckpointChunk fetches a specific chunk from an existing chekpoint.
	GetCheckpointChunk(ctx context.Context, chunk *ChunkMetadata, w io.Writer) error
}

// GetCheckpointsRequest is a GetCheckpoints request.
type GetCheckpointsRequest struct {
	Version   uint16           `json:"version"`
	Namespace common.Namespace `json:"namespace"`
}

// Creator is a checkpoint creator.
type Creator interface {
	ChunkProvider

	// CreateCheckpoint creates a new checkpoint at the given root.
	CreateCheckpoint(ctx context.Context, root node.Root, chunkSize uint64) (*Metadata, error)

	// GetCheckpoint retrieves checkpoint metadata for a specific checkpoint.
	GetCheckpoint(ctx context.Context, request *GetCheckpointRequest) (*Metadata, error)

	// DeleteCheckpoint deletes a specific checkpoint.
	DeleteCheckpoint(ctx context.Context, request *DeleteCheckpointRequest) error
}

// GetCheckpointRequest is a GetCheckpoint request.
type GetCheckpointRequest struct {
	Version uint16    `json:"version"`
	Root    node.Root `json:"root"`
}

// DeleteCheckpointRequest is a DeleteCheckpoint request.
type DeleteCheckpointRequest struct {
	Version uint16    `json:"version"`
	Root    node.Root `json:"root"`
}

// Restorer is a checkpoint restorer.
type Restorer interface {
	// StartRestore starts a checkpoint restoration process.
	StartRestore(ctx context.Context, checkpoint *Metadata) error

	// RestoreChunk restores the given chunk into the underlying node database.
	//
	// This method requires that a restoration is in progress.
	//
	// Returns true when the checkpoint has been fully restored.
	RestoreChunk(ctx context.Context, index uint64, r io.Reader) (bool, error)
}

// CreateRestorer is an interface that combines the checkpoint creator and restorer.
type CreateRestorer interface {
	Creator
	Restorer
}

type createRestorer struct {
	Creator
	Restorer
}

// NewCreateRestorer combines a checkpoint creator and a restorer.
func NewCreateRestorer(creator Creator, restorer Restorer) CreateRestorer {
	return &createRestorer{
		Creator:  creator,
		Restorer: restorer,
	}
}

// ChunkMetadata is chunk metadata.
type ChunkMetadata struct {
	Version uint16    `json:"version"`
	Root    node.Root `json:"root"`
	Index   uint64    `json:"index"`
	Digest  hash.Hash `json:"digest"`
}

// Metadata is checkpoint metadata.
type Metadata struct {
	Version uint16      `json:"version"`
	Root    node.Root   `json:"root"`
	Chunks  []hash.Hash `json:"chunks"`
}

// GetChunkMetadata returns the chunk metadata for the corresponding chunk.
func (c Metadata) GetChunkMetadata(idx uint64) (*ChunkMetadata, error) {
	if idx >= uint64(len(c.Chunks)) {
		return nil, ErrChunkNotFound
	}

	return &ChunkMetadata{
		Version: c.Version,
		Root:    c.Root,
		Index:   idx,
		Digest:  c.Chunks[int(idx)],
	}, nil
}