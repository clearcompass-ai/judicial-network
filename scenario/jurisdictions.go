package scenario

// ActiveCourts returns the currently-active Tennessee jurisdictions —
// **Davidson County (trial) → TN Supreme Court (court of last resort)** — both
// deployment-backed (tn/counties/davidson, tn/sup_ct). The active scenario
// short-circuits the intermediate appellate tier: a Davidson case appeals /
// transfers directly to the Supreme Court.
//
// The two intermediate appellate courts are BACKLOG (see BACKLOG.md):
//   - TN Court of Criminal Appeals — modeled (TennesseeCriminalAppeals: the real
//     12-judge bench) but has NO deployment yet.
//   - TN Court of Appeals — has a deployment (tn/coa) but is NOT modeled yet
//     (needs the real bench data).
//
// Federal is added after these three TN courts are fully wired.
func ActiveCourts() []Jurisdiction {
	return []Jurisdiction{
		DavidsonCounty(),
		TennesseeSupremeCourt(),
	}
}
