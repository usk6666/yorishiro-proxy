//go:build !unix

package flow

// sinkOpenNoFollow is 0 where the platform has no O_NOFOLLOW; the Lstat
// check in openFileSinkWriter still refuses a symlinked flows.jsonl.
const sinkOpenNoFollow = 0
