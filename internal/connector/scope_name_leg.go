package connector

// CheckNameLeg is a scaffolding stub (USK-1167 red commit).
func (s *TargetScope) CheckNameLeg(scheme, name string, port int, path, dialTarget string) (allowed bool, reason string) {
	return s.CheckTarget(scheme, name, port, path)
}

// CheckHostHeader is a scaffolding stub (USK-1167 red commit).
func (s *TargetScope) CheckHostHeader(scheme, value, path, dialTarget string) (allowed bool, reason string) {
	return true, ""
}
