package badger

import (
	"fmt"
	"math"

	"github.com/dgraph-io/badger/v2"

	cmnBadger "github.com/oasisprotocol/oasis-core/go/common/badger"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/keyformat"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

const flushInterval = 5000

type migratorFactory func(db *badgerNodeDB, helper MigrationHelper) migration

var (
	originVersions = map[uint64]migratorFactory{
		3: func(db *badgerNodeDB, helper MigrationHelper) migration {
			return &v4Migrator{
				meta: v4MigratorMetadata{
					Roots: map[typedHash]bool{},
				},
				db:     db,
				helper: helper,
				flushRemain: flushInterval,
			}
		},
	}

	migrationMetaKeyFmt = keyformat.New(0xff)

	v3NodeKeyFmt                    = keyformat.New(0x00, &hash.Hash{})
	v3WriteLogKeyFmt                = keyformat.New(0x01, uint64(0), &hash.Hash{}, &hash.Hash{})
	v3RootsMetadataKeyFmt           = keyformat.New(0x02, uint64(0))
	v3RootUpdatedNodesKeyFmt        = keyformat.New(0x03, uint64(0), &hash.Hash{})
	v3MetadataKeyFmt                = keyformat.New(0x04)
	v3MultipartRestoreNodeLogKeyFmt = keyformat.New(0x05, &hash.Hash{})

	v4NodeKeyFmt                    = nodeKeyFmt
	v4WriteLogKeyFmt                = writeLogKeyFmt
	v4RootsMetadataKeyFmt           = rootsMetadataKeyFmt
	v4RootUpdatedNodesKeyFmt        = rootUpdatedNodesKeyFmt
	v4MetadataKeyFmt                = metadataKeyFmt
	v4MultipartRestoreNodeLogKeyFmt = multipartRestoreNodeLogKeyFmt
)

type v3RootsMetadata struct {
	_ struct{} `cbor:",toarray"`

	Roots map[hash.Hash][]hash.Hash
}

type v4RootsMetadata = rootsMetadata

type v3UpdatedNode struct {
	_ struct{} `cbor:",toarray"` // nolint

	Removed bool
	Hash    hash.Hash
}

type v4UpdatedNode = updatedNode

// No change in metadata format between versions 3 and 4.
type v3SerializedMetadata = serializedMetadata

type v4SerializedMetadata = serializedMetadata

type MigrationHelper interface {
	GetRootForHash(root hash.Hash, version uint64) (node.Root, error)

	ReportStatus(msg string)
	ReportProgress(msg string, current, total uint64)
}

type migration interface {
	Migrate() (uint64, error)
}

type migrationCommonMeta struct {
	// An item with this key should always exist in the metadata blob.
	// It is the original version of the database, before the migration started,
	// so the migration driver can choose the correct migration to resume with
	// even in cases where the database metadata key was already migrated.
	BaseDBVersion uint64 `json:"base_version"`
}

type treeWalkItem struct {
	Type node.RootType `json:"root_type"`
	Hash hash.Hash     `json:"root_hash"`
}

type v4MigratorMetadata struct {
	migrationCommonMeta

	Roots map[typedHash]bool `json:"roots"`

	InitComplete bool `json:"init_complete"`
	MetaComplete bool `json:"meta_complete"`
	TreeComplete bool `json:"tree_complete"`

	LastKey []byte `json:"last_key"`

	TreeStack []treeWalkItem `json:"tree_walk_item"`

	MetaCount        uint64 `json:"meta_count"`
	TreeCount        uint64 `json:"tree_count"`
	CurrentTreeCount uint64 `json:"current_tree_count"`
	CurrentMetaCount uint64 `json:"current_meta_count"`
}

func (m *v4MigratorMetadata) load(db *badger.DB) error {
	txn := db.NewTransactionAt(tsMetadata, false)
	defer txn.Discard()

	item, err := txn.Get(migrationMetaKeyFmt.Encode())
	if err != nil {
		return err
	}

	return item.Value(func(data []byte) error {
		return cbor.Unmarshal(data, m)
	})
}

func (m *v4MigratorMetadata) save(batch *badger.WriteBatch) error {
	return batch.SetEntryAt(badger.NewEntry(
		migrationMetaKeyFmt.Encode(),
		cbor.Marshal(m),
	), tsMetadata)
}

func (m *v4MigratorMetadata) remove(batch *badger.WriteBatch) error {
	return batch.DeleteAt(migrationMetaKeyFmt.Encode(), tsMetadata)
}

type v4Migrator struct {
	db     *badgerNodeDB
	helper MigrationHelper

	readTxn     *badger.Txn
	changeBatch *badger.WriteBatch
	flushRemain int

	meta v4MigratorMetadata
}

func (v4 *v4Migrator) flush(force bool) error {
	v4.flushRemain--
	if v4.flushRemain < 0 || force {
		v4.flushRemain = flushInterval
		if err := v4.changeBatch.Flush(); err != nil {
			return fmt.Errorf("mkvs/badger/migrate: error flushing progress: %w", err)
		}
		v4.changeBatch = v4.db.db.NewWriteBatchAt(tsMetadata)
	}
	return nil
}

// This is only usable once rootsMetadataKeyFmt keys have been migrated!
func (v4 *v4Migrator) getRootType(rh hash.Hash, version uint64) (node.RootType, error) {
	root, err := v4.helper.GetRootForHash(rh, version)
	if err == nil {
		return root.Type, nil
	}

	// If not directly discoverable, try traversing finalized roots metadata.
	meta, err := loadRootsMetadata(v4.readTxn, version)
	if err != nil {
		return node.RootTypeInvalid, err
	}

	for root, chain := range meta.Roots {
		h := root.Hash()
		if h.Equal(&rh) {
			return root.Type(), nil
		}
		for _, droot := range chain {
			h := droot.Hash()
			if h.Equal(&rh) {
				return droot.Type(), nil
			}
		}
	}

	return node.RootTypeInvalid, fmt.Errorf("mkvs/badger/migrate: root %v not found in block roots or finalized version metadata", rh)
}

func (v4 *v4Migrator) keyMetadata(item *badger.Item) error {
	var meta3 v3SerializedMetadata
	err := item.Value(func(data []byte) error {
		return cbor.UnmarshalTrusted(data, &meta3)
	})
	if err != nil {
		return fmt.Errorf("mkvs/badger/migrate: error decoding database metadata: %w", err)
	}

	var meta4 v4SerializedMetadata
	meta4 = meta3
	meta4.Version = 4

	entry := badger.NewEntry(
		v4MetadataKeyFmt.Encode(),
		cbor.Marshal(meta4),
	)
	err = v4.changeBatch.SetEntryAt(entry, item.Version())
	if err != nil {
		return fmt.Errorf("mkvs/badger/migrate: error storing updated database metadata: %w", err)
	}

	return nil
}

func (v4 *v4Migrator) keyRootsMetadata(item *badger.Item) error {
	var version uint64
	if !v3RootsMetadataKeyFmt.Decode(item.Key(), &version) {
		return fmt.Errorf("mkvs/badger/migrate: error decoding roots metadata key")
	}

	var rootsMeta v3RootsMetadata
	err := item.Value(func(data []byte) error {
		return cbor.UnmarshalTrusted(data, &rootsMeta)
	})
	if err != nil {
		return fmt.Errorf("mkvs/badger/migrate: error deserializing roots metadata: %w", err)
	}

	// Propagate type information throughout the derived root chains.
	plainRoots := map[hash.Hash]node.RootType{}
	for root, chain := range rootsMeta.Roots {
		plainRoots[root] = node.RootTypeInvalid
		for _, droot := range chain {
			plainRoots[droot] = node.RootTypeInvalid
		}
	}

	remaining := len(plainRoots)
	for root, typ := range plainRoots {
		if typ != node.RootTypeInvalid {
			continue
		}
		full, err := v4.helper.GetRootForHash(root, version)
		if err == nil {
			plainRoots[root] = full.Type
			remaining--
		}
	}

	for remaining > 0 {
		preLoop := remaining
		for root, chain := range rootsMeta.Roots {
			typ := node.RootTypeInvalid
			all := append([]hash.Hash{root}, chain...)
			for _, droot := range all {
				if dtype, ok := plainRoots[droot]; ok && dtype != node.RootTypeInvalid {
					typ = dtype
					break
				}
			}

			if typ != node.RootTypeInvalid {
				for _, root := range all {
					if plainRoots[root] == node.RootTypeInvalid {
						plainRoots[root] = typ
						remaining--
					}
				}
			}
		}

		if remaining == preLoop {
			for r, t := range plainRoots {
				fmt.Printf("plainroot %v has type %v\n", r, t)
			}
			fmt.Printf("full roots struct is %v\n", rootsMeta.Roots)
			return fmt.Errorf("mkvs/badger/migrate: can't convert roots metadata for version %d: not all types found", version)
		}
	}

	// Build new roots structure.
	var newRoots v4RootsMetadata
	newRoots.Roots = map[typedHash][]typedHash{}
	for root, chain := range rootsMeta.Roots {
		arr := make([]typedHash, 0, len(chain))
		for _, droot := range chain {
			th := typedHashFromParts(plainRoots[droot], droot)
			v4.meta.Roots[th] = true
			arr = append(arr, th)
		}
		th := typedHashFromParts(plainRoots[root], root)
		v4.meta.Roots[th] = true
		newRoots.Roots[th] = arr
	}

	entry := badger.NewEntry(v4RootsMetadataKeyFmt.Encode(&version), cbor.Marshal(newRoots))
	err = v4.changeBatch.SetEntryAt(entry, item.Version())
	if err != nil {
		return fmt.Errorf("mkvs/badger/migrate: error storing updated root metadata: %w", err)
	}
	err = v4.changeBatch.DeleteAt(item.Key(), item.Version())
	if err != nil {
		return fmt.Errorf("mkvs/badger/migrate: error removing old root metadata: %w", err)
	}

	return nil
}

func (v4 *v4Migrator) keyWriteLog(item *badger.Item) error {
	var version uint64
	var h1, h2 hash.Hash
	var th1, th2 typedHash
	if !v3WriteLogKeyFmt.Decode(item.Key(), &version, &h1, &h2) {
		return fmt.Errorf("mkvs/badger/migrate: error decoding writelog key")
	}

	var val []byte
	_ = item.Value(func(data []byte) error {
		val = data
		return nil
	})

	t1, err := v4.getRootType(h1, version)
	if err != nil {
		return fmt.Errorf("mkvs/badger/migrate: error getting type for writelog root %v: %w", h1, err)
	}
	th1.FromParts(t1, h1)
	th2.FromParts(t1, h2)

	entry := badger.NewEntry(v4WriteLogKeyFmt.Encode(&version, &th1, &th2), val)
	err = v4.changeBatch.SetEntryAt(entry, item.Version())
	if err != nil {
		return fmt.Errorf("mkvs/badger/migrate: error setting updated writelog key: %w", err)
	}
	err = v4.changeBatch.DeleteAt(item.Key(), item.Version())
	if err != nil {
		return fmt.Errorf("mkvs/badger/migrate: error removing old writelog key: %w", err)
	}

	return nil
}

func (v4 *v4Migrator) keyRootUpdatedNodes(item *badger.Item) error {
	fmt.Println("running roots metadata migrator")
	var version uint64
	var h1 hash.Hash
	if !v3RootUpdatedNodesKeyFmt.Decode(item.Key(), &version, &h1) {
		return fmt.Errorf("mkvs/badger/migrate: error decoding root updated nodes key")
	}

	var oldUpdatedNodes []v3UpdatedNode
	err := item.Value(func(data []byte) error {
		return cbor.UnmarshalTrusted(data, &oldUpdatedNodes)
	})
	if err != nil {
		return fmt.Errorf("mkvs/badger/migrate: error decoding updated nodes list for root %v:%v: %w", h1, version, err)
	}

	typ, err := v4.getRootType(h1, version)
	if err != nil {
		return fmt.Errorf("mkvs/badger/migrate: error getting root %v:%v for updated nodes list: %w", h1, version, err)
	}
	th := typedHashFromParts(typ, h1)
	v4.meta.Roots[th] = true

	newUpdatedNodes := make([]v4UpdatedNode, 0, len(oldUpdatedNodes))
	for _, up := range oldUpdatedNodes {
		newUpdatedNodes = append(newUpdatedNodes, v4UpdatedNode{
			Removed: up.Removed,
			Hash:    typedHashFromParts(typ, up.Hash),
		})
	}

	entry := badger.NewEntry(
		v4RootUpdatedNodesKeyFmt.Encode(version, &th),
		cbor.Marshal(newUpdatedNodes),
	)
	err = v4.changeBatch.SetEntryAt(entry, item.Version())
	if err != nil {
		return fmt.Errorf("mkvs/badger/migrate: error storing updated nodes list for root %v: %w", th, err)
	}
	err = v4.changeBatch.DeleteAt(item.Key(), item.Version())
	if err != nil {
		return fmt.Errorf("mkvs/badger/migrate: error deleting old nodes nodes list for root %v: %w", th, err)
	}

	return nil
}

func (v4 *v4Migrator) migrateMeta() error {
	v4.helper.ReportStatus("migrating storage roots and metadata")

	keyOrder := []byte{
		v3MetadataKeyFmt.Prefix(),
		v3RootsMetadataKeyFmt.Prefix(),
		v3WriteLogKeyFmt.Prefix(),
		v3RootUpdatedNodesKeyFmt.Prefix(),
		// nodeKeyFmt and multipartRestoreNodeLogKeyFmt keys
		// will be migrated during tree node migration.
	}
	skipFirst := true
	if len(v4.meta.LastKey) == 0 {
		v4.meta.LastKey = []byte{keyOrder[0]}
		// LastKey records the last _already processed_ key, so
		// if we're only just starting up, the first key we see
		// won't have been processed yet.
		skipFirst = false
	}

	keyNexts := map[byte]byte{}
	for i := 0; i < len(keyOrder)-1; i++ {
		keyNexts[keyOrder[i]] = keyOrder[i+1]
	}

	keyFuncs := map[byte]func(item *badger.Item)error{
		v3MetadataKeyFmt.Prefix(): v4.keyMetadata,
		v3RootsMetadataKeyFmt.Prefix(): v4.keyRootsMetadata,
		v3WriteLogKeyFmt.Prefix(): v4.keyWriteLog,
		v3RootUpdatedNodesKeyFmt.Prefix(): v4.keyRootUpdatedNodes,
	}

	it := v4.readTxn.NewIterator(badger.DefaultIteratorOptions)
	defer func() {
		it.Close()
	}()

	currentKey := v4.meta.LastKey[0]
	keyOk := true
	for {
		it.Rewind()
		it.Seek(v4.meta.LastKey)
		for ; it.Valid(); it.Next() {
			if skipFirst {
				skipFirst = false
				continue
			}
			if it.Item().Key()[0] != currentKey {
				break
			}

			if err := keyFuncs[currentKey](it.Item()); err != nil {
				return err
			}

			v4.meta.CurrentMetaCount++
			v4.helper.ReportProgress("updated keys", v4.meta.CurrentMetaCount, v4.meta.MetaCount)
			v4.meta.LastKey = it.Item().KeyCopy(v4.meta.LastKey)
			if err := v4.meta.save(v4.changeBatch); err != nil {
				return fmt.Errorf("mkvs/badger/migrate: error saving migration metadata: %w", err)
			}

			// Save progress.
			if err := v4.flush(false); err != nil {
				return err
			}
		}

		// Force flush everything.
		if err := v4.flush(true); err != nil {
			return err
		}
		it.Close()
		v4.readTxn.Discard()
		v4.readTxn = v4.db.db.NewTransactionAt(math.MaxUint64, false)
		it = v4.readTxn.NewIterator(badger.DefaultIteratorOptions)

		currentKey, keyOk = keyNexts[currentKey]
		if !keyOk {
			break
		}
		v4.meta.LastKey = []byte{currentKey}
	}

	return nil
}

func (v4 *v4Migrator) migrateTree() error {
	it := v4.readTxn.NewIterator(badger.DefaultIteratorOptions)
	defer it.Close()
	v4.helper.ReportStatus("migrating tree nodes")

	// Load all tree roots on the walk stack, if they're not there already.
	if v4.meta.TreeStack == nil {
		v4.meta.CurrentTreeCount = 0
		for root := range v4.meta.Roots {
			v4.meta.TreeStack = append(v4.meta.TreeStack, treeWalkItem{
				Type: root.Type(),
				Hash: root.Hash(),
			})
		}
		if err := v4.meta.save(v4.changeBatch); err != nil {
			return err
		}
	}

	// Flattened tree recursion.
	for len(v4.meta.TreeStack) > 0 {
		twi := v4.meta.TreeStack[len(v4.meta.TreeStack)-1]
		v4.meta.TreeStack = v4.meta.TreeStack[:len(v4.meta.TreeStack)-1]

		th := typedHashFromParts(twi.Type, twi.Hash)

		// Trivial: see if this node appears in an on-going multipart restore.
		multipartKey := v3MultipartRestoreNodeLogKeyFmt.Encode(&twi.Hash)
		if item, err := v4.readTxn.Get(multipartKey); err == nil {
			err = v4.changeBatch.DeleteAt(multipartKey, item.Version())
			if err != nil {
				return err
			}
			var value []byte
			_ = item.Value(func(data []byte) error {
				value = data
				return nil
			})
			entry := badger.NewEntry(
				v4MultipartRestoreNodeLogKeyFmt.Encode(&th),
				value,
			)
			err = v4.changeBatch.SetEntryAt(entry, item.Version())
			if err != nil {
				return err
			}

			v4.meta.CurrentTreeCount++
		}

		// Node processing and tree walk.
		nodeKey := v3NodeKeyFmt.Encode(&twi.Hash)
		if item, err := v4.readTxn.Get(nodeKey); err == nil {
			var n node.Node
			var value []byte
			err = item.Value(func(data []byte) error {
				var nerr error
				value = data
				n, nerr = node.UnmarshalBinary(data)
				return nerr
			})
			if err != nil {
				return err
			}

			err = v4.changeBatch.DeleteAt(nodeKey, item.Version())
			if err != nil {
				return err
			}
			entry := badger.NewEntry(
				v4NodeKeyFmt.Encode(&th),
				value,
			)
			err = v4.changeBatch.SetEntryAt(entry, item.Version())
			if err != nil {
				return err
			}

			switch nn := n.(type) {
			case *node.LeafNode:
				// Nothing to do here.

			case *node.InternalNode:
				children := make([]hash.Hash, 0, 3)
				if nn.LeafNode != nil {
					children = append(children, nn.LeafNode.Hash)
				}
				if nn.Left != nil {
					children = append(children, nn.Left.Hash)
				}
				if nn.Right != nil {
					children = append(children, nn.Right.Hash)
				}
				for _, child := range children {
					v4.meta.TreeStack = append(v4.meta.TreeStack, treeWalkItem{
						Type: twi.Type,
						Hash: child,
					})
				}
			}

			v4.meta.CurrentTreeCount++
		}

		if err := v4.meta.save(v4.changeBatch); err != nil {
			return fmt.Errorf("mkvs/badger/migrate: error saving migrator state: %w", err)
		}
		if err := v4.flush(false); err != nil {
			return err
		}
		// The count of currently processed nodes here might over- or undershoot since
		// we have a read transaction that's stuck in the past. But node hashes aren't
		// supposed to come up more than once, so it should be approximately correct.
		v4.helper.ReportProgress("updated tree nodes", v4.meta.CurrentTreeCount, v4.meta.TreeCount)
	}

	return nil
}

func (v4 *v4Migrator) Migrate() (rversion uint64, rerr error) {
	v4.readTxn = v4.db.db.NewTransactionAt(math.MaxUint64, false)
	defer func() {
		// readTxn will change throughout the process, don't
		// bind the defer to a particular instance.
		v4.readTxn.Discard()
	}()
	v4.changeBatch = v4.db.db.NewWriteBatchAt(tsMetadata)
	defer func() {
		// changeBatch will change throughout the process, don't
		// bind the defer to a particular instance.
		v4.changeBatch.Cancel()
	}()

	// Load migration metadata and set up saving on function return.
	err := v4.meta.load(v4.db.db)
	if err != nil && err != badger.ErrKeyNotFound {
		return 0, err
	}
	v4.meta.BaseDBVersion = 3


	// Count keys first, so we can report some sensible progress to the user.
	// Badger says this should be fast.
	if !v4.meta.InitComplete {
		v4.helper.ReportStatus("scanning database")
		v4.meta.TreeCount = 0
		v4.meta.MetaCount = 0
		func() {
			it := v4.readTxn.NewIterator(badger.DefaultIteratorOptions)
			defer it.Close()
			for it.Rewind(); it.Valid(); it.Next() {
				prefix := it.Item().Key()[0]
				if prefix == v3NodeKeyFmt.Prefix() || prefix == v3MultipartRestoreNodeLogKeyFmt.Prefix() {
					v4.meta.TreeCount++
				} else {
					v4.meta.MetaCount++
				}
			}
		}()
		v4.meta.InitComplete = true
		if err := v4.meta.save(v4.changeBatch); err != nil {
			return 0, err
		}
		v4.helper.ReportStatus(fmt.Sprintf("%v meta keys, %v tree keys", v4.meta.MetaCount, v4.meta.TreeCount))
	}

	// Migrate!

	if !v4.meta.MetaComplete {
		if err := v4.migrateMeta(); err != nil {
			return 0, err
		}
		v4.meta.MetaComplete = true
		if err := v4.meta.save(v4.changeBatch); err != nil {
			return 0, err
		}
		if err := v4.flush(true); err != nil {
			return 0, err
		}
	}

	if !v4.meta.TreeComplete {
		if err := v4.migrateTree(); err != nil {
			return 0, fmt.Errorf("mkvs/badger/migrate: error walking node trees: %w", err)
		}
		v4.meta.TreeComplete = true
		if err := v4.meta.save(v4.changeBatch); err != nil {
			return 0, fmt.Errorf("mkvs/badger/migrate: error saving migration metadata: %w", err)
		}
	}

	// All done, flush and clean up. The metadata blob will be removed
	// in the defer handler.
	if err := v4.meta.remove(v4.changeBatch); err != nil {
		return 0, fmt.Errorf("mkvs/badger/migrate: error removing migration metadata: %w", err)
	}
	if err := v4.flush(true); err != nil {
		return 0, err
	}
	return 4, nil
}

func Migrate(cfg *api.Config, helper MigrationHelper) (uint64, error) {
	db := &badgerNodeDB{
		logger:           logging.GetLogger("mkvs/db/badger/migrate"),
		namespace:        cfg.Namespace,
		discardWriteLogs: cfg.DiscardWriteLogs,
	}
	opts := commonConfigToBadgerOptions(cfg, db)

	var err error
	if db.db, err = badger.OpenManaged(opts); err != nil {
		return 0, fmt.Errorf("mkvs/badger/migrate: failed to open database: %w", err)
	}

	// Make sure that we can discard any deleted/invalid metadata.
	db.db.SetDiscardTs(tsMetadata)

	db.gc = cmnBadger.NewGCWorker(db.logger, db.db)
	defer db.Close()

	// Load metadata.
	lastVersion, err := func() (uint64, error) {
		tx := db.db.NewTransactionAt(tsMetadata, false)
		defer tx.Discard()

		var migMeta migrationCommonMeta
		item, rerr := tx.Get(migrationMetaKeyFmt.Encode())
		if rerr == nil {
			rerr = item.Value(func(data []byte) error {
				return cbor.UnmarshalTrusted(data, &migMeta)
			})
			if rerr != nil {
				return 0, rerr
			}
			return migMeta.BaseDBVersion, nil
		}

		item, rerr = tx.Get(metadataKeyFmt.Encode())
		if rerr != nil {
			return 0, rerr
		}

		var meta metadata

		rerr = item.Value(func(data []byte) error {
			return cbor.UnmarshalTrusted(data, &meta.value)
		})
		if rerr != nil {
			return 0, rerr
		}

		return meta.value.Version, nil
	}()
	if err != nil {
		return 0, fmt.Errorf("mkvs/badger/migrate: error probing current database version: %w", err)
	}

	// Main upgrade loop.
	for lastVersion != dbVersion {
		migratorFactory := originVersions[lastVersion]
		if migratorFactory == nil {
			return 0, fmt.Errorf("mkvs/badger/migrate: unsupported version %d", lastVersion)
		}
		migrator := migratorFactory(db, helper)

		newVersion, err := migrator.Migrate()
		if err != nil {
			return 0, fmt.Errorf("mkvs/badger/migrate: error while migrating from version %d: %w", lastVersion, err)
		}
		lastVersion = newVersion
	}

	return lastVersion, nil
}
