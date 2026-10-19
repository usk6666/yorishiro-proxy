package pipeline

import "context"

// annotationsKey is the private context.Context key under which
// Pipeline.RunWithBlockedBy installs the per-Run *annotationBag.
//
// Result.Annotations is the generic Step → RecordStep channel (USK-1109):
// a Step that lets an envelope continue but wants the observation kept on
// the recorded Stream returns Annotations; the Run loop merges them into
// the bag; RecordStep appends the merged set to the Stream's tags via
// flow.StreamUpdate.AppendTags. Annotations never touch env, env.Raw or
// env.Message, so they are invisible to the wire and to variant
// detection.
//
// Lifetime — bounded to one Pipeline.Run call, like snapshotKey and
// wireEncodedKey. The Step loop is single-goroutine per envelope, so the
// map needs no synchronization.
type annotationsKey struct{}

type annotationBag struct {
	tags map[string]string
}

// withAnnotations installs a fresh, empty bag in ctx.
func withAnnotations(ctx context.Context) context.Context {
	return context.WithValue(ctx, annotationsKey{}, &annotationBag{})
}

// mergeAnnotations copies tags into the bag in ctx. Later Steps win on a
// key collision. No-op when ctx was not produced by Pipeline.Run or tags
// is empty.
func mergeAnnotations(ctx context.Context, tags map[string]string) {
	if len(tags) == 0 {
		return
	}
	bag, _ := ctx.Value(annotationsKey{}).(*annotationBag)
	if bag == nil {
		return
	}
	if bag.tags == nil {
		bag.tags = make(map[string]string, len(tags))
	}
	for k, v := range tags {
		bag.tags[k] = v
	}
}

// annotationsFromContext returns the merged annotations of the current
// Run, or nil when there are none (or ctx was not produced by
// Pipeline.Run). The returned map is the bag's own; callers must not
// mutate it.
func annotationsFromContext(ctx context.Context) map[string]string {
	bag, _ := ctx.Value(annotationsKey{}).(*annotationBag)
	if bag == nil || len(bag.tags) == 0 {
		return nil
	}
	return bag.tags
}

// copyAnnotations returns an independent copy of tags, or nil when empty.
func copyAnnotations(tags map[string]string) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	out := make(map[string]string, len(tags))
	for k, v := range tags {
		out[k] = v
	}
	return out
}

// blockAnnotationsKey carries RunOutcome.Annotations from the session loop
// to the block recorder (session.SessionOptions.OnPipelineDrop) without
// widening that callback's signature (USK-1109 review F-2).
type blockAnnotationsKey struct{}

// WithBlockAnnotations returns ctx carrying tags for the block recorder.
// Returns ctx unchanged when tags is empty.
func WithBlockAnnotations(ctx context.Context, tags map[string]string) context.Context {
	if len(tags) == 0 {
		return ctx
	}
	return context.WithValue(ctx, blockAnnotationsKey{}, tags)
}

// BlockAnnotationsFromContext returns the tags installed by
// WithBlockAnnotations, or nil. Callers must not mutate the map.
func BlockAnnotationsFromContext(ctx context.Context) map[string]string {
	tags, _ := ctx.Value(blockAnnotationsKey{}).(map[string]string)
	return tags
}
