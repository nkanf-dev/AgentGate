package types

// SideEffect represents a runtime side effect that an action may produce.
type SideEffect string

const (
	SideEffectNetworkEgress   SideEffect = "network_egress"
	SideEffectFilesystemWrite SideEffect = "filesystem_write"
	SideEffectProcessSpawn    SideEffect = "process_spawn"
	SideEffectSecretResolve   SideEffect = "secret_resolve"
)

// AllSideEffects returns all known side effect values.
func AllSideEffects() []SideEffect {
	return []SideEffect{
		SideEffectNetworkEgress,
		SideEffectFilesystemWrite,
		SideEffectProcessSpawn,
		SideEffectSecretResolve,
	}
}
