package scenario

// TennesseeCourts returns the three Tennessee jurisdictions modeled so far,
// trial → intermediate appellate → court of last resort: the Davidson County
// trial courts, the Court of Criminal Appeals, and the Supreme Court. (Federal
// is added once these three are fully wired through the seeder + generators.)
//
// Deployment status: Davidson (tn/counties/davidson) and the Supreme Court
// (tn/sup_ct) have bundles; the Court of Criminal Appeals does NOT yet — its
// bundle must be created before its officers can be seeded (see
// criminalAppealsExchangeDID).
func TennesseeCourts() []Jurisdiction {
	return []Jurisdiction{
		DavidsonCounty(),
		TennesseeCriminalAppeals(),
		TennesseeSupremeCourt(),
	}
}
