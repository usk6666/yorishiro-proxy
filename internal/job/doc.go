// Package job defines the execution unit for resend/fuzz operations.
//
// Job is NOT a Pipeline Step — it is a separate execution layer that wraps
// the Pipeline with Macro hook support (pre-send, post-receive).
//
// Normal proxy traffic flows through:
//
//	Connector → RunSession(client Channel, dial, pipeline)
//
// Resend/fuzz traffic flows through:
//
//	Job(EnvelopeSource, dial, pipeline, macro hooks).Run()
//
// Job has its own send/receive loop and does NOT use RunSession (which is
// designed for bidirectional proxy sessions). Each iteration:
//
//  1. Source.Next() yields the next Envelope to send
//  2. Pre-send macro hook fires (if configured and RunInterval matches)
//  3. Pipeline.Run processes the send Envelope
//  4. Dial upstream → Channel.Send → Channel.Next (response)
//  5. Pipeline.Run processes the response Envelope
//  6. Post-receive macro hook fires (if configured and RunInterval matches)
//  7. HookState updated for RunInterval evaluation on next iteration
//
// Macro hooks are Job-level concerns because:
//   - Macros are specified per Job (not applied to normal proxy traffic)
//   - RunInterval (once, every_n, on_error, on_status) requires Job-level state
//   - Post-receive runs after Pipeline completion
//   - Macros are inherently stateful (KV Store shared across hooks)
//
// Macro internal requests use Pipeline.Without(InterceptStep). All other Steps
// (HostScope, Safety, Transform, Record) still apply to Macro traffic.
package job
