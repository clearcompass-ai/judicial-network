/*
FILE PATH: topology/network.go
DESCRIPTION: Federal/state/county/municipal/tribal jurisdiction hierarchy.
    Pure data model — no SDK calls. Defines the Tennessee judicial network
    topology used by anchor_publisher.go and discovery.go.
KEY ARCHITECTURAL DECISIONS: No SDK imports. Pure domain data types.
OVERVIEW: JurisdictionLevel, JurisdictionNode, hierarchy traversal.
KEY DEPENDENCIES: none (pure types)
*/
package topology

// JurisdictionLevel classifies a court's position in the hierarchy.
type JurisdictionLevel int

const (
	LevelFederal    JurisdictionLevel = iota
	LevelState
	LevelCounty
	LevelMunicipal
	LevelTribal
)

// JurisdictionNode represents one court or jurisdiction in the hierarchy.
type JurisdictionNode struct {
	DID        string            // DID of this jurisdiction's log
	Name       string            // Human-readable name
	Level      JurisdictionLevel // Position in hierarchy
	ParentDID  string            // DID of parent jurisdiction (empty for root)
	ChildDIDs  []string          // DIDs of child jurisdictions
	AnchorDID  string            // DID of anchor log this court publishes to
	Region     string            // Geographic region (e.g., "Middle Tennessee")
	FIPSCode   string            // FIPS county code (for county level)
}

// Hierarchy is the complete jurisdiction tree rooted at the state level.
type Hierarchy struct {
	Root     *JurisdictionNode
	ByDID    map[string]*JurisdictionNode
	ByLevel  map[JurisdictionLevel][]*JurisdictionNode
}

// NewHierarchy creates an empty hierarchy.
func NewHierarchy() *Hierarchy {
	return &Hierarchy{
		ByDID:   make(map[string]*JurisdictionNode),
		ByLevel: make(map[JurisdictionLevel][]*JurisdictionNode),
	}
}

// Add registers a node in the hierarchy.
func (h *Hierarchy) Add(node *JurisdictionNode) {
	h.ByDID[node.DID] = node
	h.ByLevel[node.Level] = append(h.ByLevel[node.Level], node)
	if node.ParentDID == "" {
		h.Root = node
	}
}

// Parent returns the parent node, or nil.
func (h *Hierarchy) Parent(did string) *JurisdictionNode {
	node, ok := h.ByDID[did]
	if !ok || node.ParentDID == "" {
		return nil
	}
	return h.ByDID[node.ParentDID]
}

// AnchorChain returns the anchor path from a county log up to the state root.
func (h *Hierarchy) AnchorChain(did string) []string {
	var chain []string
	current := did
	visited := make(map[string]bool)
	for current != "" && !visited[current] {
		visited[current] = true
		chain = append(chain, current)
		node, ok := h.ByDID[current]
		if !ok {
			break
		}
		current = node.AnchorDID
	}
	return chain
}
