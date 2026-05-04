package proxy

import "github.com/usk6666/yorishiro-proxy/internal/connector"

// BudgetConfig is a type alias for connector.BudgetConfig. The canonical
// definition (struct, JSON marshalers, validation) lives in
// internal/connector/budget.go (rehomed by USK-704). Kept aliased here so
// the legacy package's existing test file and the still-aliased mcp test
// scaffolding continue to compile until USK-708/USK-697 retire them.
type BudgetConfig = connector.BudgetConfig

// BudgetManager is a type alias for connector.BudgetManager. See
// BudgetConfig above for context.
type BudgetManager = connector.BudgetManager

// NewBudgetManager forwards to connector.NewBudgetManager so that legacy
// callers that wrote `proxy.NewBudgetManager()` keep working through the
// USK-708 / USK-697 deletion windows.
func NewBudgetManager() *BudgetManager {
	return connector.NewBudgetManager()
}
