//go:build unix

package flow

import "syscall"

// sinkOpenNoFollow makes opening flows.jsonl fail when it is a symlink.
const sinkOpenNoFollow = syscall.O_NOFOLLOW
