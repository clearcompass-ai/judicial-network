/*
FILE PATH: schemas/shard_genesis.go
DESCRIPTION: shard-genesis-v1 wrapping SDK's ShardGenesisPayload.
KEY ARCHITECTURAL DECISIONS: Delegates to SDK schema.ParseShardGenesisPayload.
OVERVIEW: Registers shard-genesis-v1 for topology/anchor_publisher.go.
KEY DEPENDENCIES: ortholog-sdk/schema
*/
package schemas

import (
	"encoding/json"
	sdkschema "github.com/clearcompass-ai/ortholog-sdk/schema"
)

const SchemaShardGenesisV1 = "shard-genesis-v1"

func DefaultShardGenesisParams() []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"identifier_scope": "real_did",
		"migration_policy": "strict",
	})
	return b
}

func shardGenesisRegistration() *SchemaRegistration {
	return &SchemaRegistration{
		URI: SchemaShardGenesisV1,
		Serialize: func(payload interface{}) ([]byte, error) {
			p, ok := payload.(*sdkschema.ShardGenesisPayload)
			if !ok { return nil, ErrDeserialize }
			return json.Marshal(p)
		},
		Deserialize:     func(data []byte) (interface{}, error) { return sdkschema.ParseShardGenesisPayload(data) },
		DefaultParams:   DefaultShardGenesisParams,
		IdentifierScope: IdentifierScopeRealDID,
	}
}
