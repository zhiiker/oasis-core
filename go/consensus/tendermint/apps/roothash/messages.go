package roothash

import (
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	roothashApi "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/roothash/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func (app *rootHashApplication) processRuntimeMessages(
	ctx *tmapi.Context,
	rtState *roothash.RuntimeState,
	msgs []block.Message,
) error {
	// Prepare a new context for processing messages.
	msgCtx := ctx.WithCallerAddress(staking.NewRuntimeAddress(rtState.Runtime.ID))
	msgCtx.SetGasAccountant(tmapi.NewNopGasAccountant()) // Gas was already accounted for.
	defer msgCtx.Close()

	for i, msg := range msgs {
		var err error
		switch {
		case msg.Noop != nil:
			err = app.md.Publish(msgCtx, roothashApi.RuntimeMessageNoop, &msg.Noop)
		case msg.Staking != nil:
			err = app.md.Publish(msgCtx, roothashApi.RuntimeMessageStaking, &msg.Staking)
		default:
			// Unsupported message.
			err = roothash.ErrInvalidArgument
		}
		if err != nil {
			ctx.Logger().Warn("failed to process runtime message",
				"err", err,
				"runtime_id", rtState.Runtime.ID,
				"msg_index", i,
			)
		}

		// Make sure somebody actually handled the message, otherwise treat as unsupported.
		if err == tmapi.ErrNoSubscribers {
			err = roothash.ErrInvalidArgument
		}

		module, code := errors.Code(err)
		evV := ValueMessage{
			ID: rtState.Runtime.ID,
			Event: roothash.MessageEvent{
				Index:  uint32(i),
				Module: module,
				Code:   code,
			},
		}
		ctx.EmitEvent(
			tmapi.NewEventBuilder(app.Name()).
				Attribute(KeyMessage, cbor.Marshal(evV)).
				Attribute(KeyRuntimeID, ValueRuntimeID(evV.ID)),
		)
	}
	return nil
}
