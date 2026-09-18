package kvpath_test

import (
	"errors"
	"testing"

	"github.com/goodtune/dotvault/internal/kvpath"
)

func TestEditPolicyStrictSubtree(t *testing.T) {
	p := kvpath.NewEditPolicy([]string{"personal", "scratch"}, nil)

	for _, ok := range []string{
		"personal/token",
		"scratch/todo",
	} {
		if clean, err := p.Allow(ok); err != nil {
			t.Errorf("Allow(%q) = %v, want nil", ok, err)
		} else if clean != ok {
			t.Errorf("Allow(%q) cleaned to %q", ok, clean)
		}
	}

	// The root of the key space, the roots themselves, and anything outside
	// them are all refused. A root naming a folder must not make the secret
	// of the same name — a direct child of the key-space root — editable.
	for _, refused := range []string{
		"",
		"personal",
		"scratch",
		"gh",
		"personalish/token",
		"other/personal/token",
	} {
		if _, err := p.Allow(refused); !errors.Is(err, kvpath.ErrNotEditable) {
			t.Errorf("Allow(%q) = %v, want ErrNotEditable", refused, err)
		}
	}
}

// The user's key space is one folder deep — an enrolment key is flat ("gh") or
// grouped exactly once ("databricks/prod") and never more, and editing is a
// view onto that layout rather than a second one. So a secret is exactly one
// segment below its root: "personal/aws/dev" is not a path this policy grants,
// and it is refused for being too deep rather than for being outside the
// subtree, because the two are different things to tell a user.
func TestEditPolicyAdmitsOnlyDirectChildrenOfARoot(t *testing.T) {
	p := kvpath.NewEditPolicy([]string{"personal"}, nil)

	if _, err := p.Allow("personal/token"); err != nil {
		t.Errorf("Allow(personal/token) = %v, want nil", err)
	}
	for _, deep := range []string{
		"personal/aws/dev",
		"personal/a/b/c",
	} {
		_, err := p.Allow(deep)
		if !errors.Is(err, kvpath.ErrSecretDepth) {
			t.Errorf("Allow(%q) = %v, want ErrSecretDepth", deep, err)
		}
		if p.Allows(deep) {
			t.Errorf("Allows(%q) = true, want false", deep)
		}
	}
	// A folder below a root is not a folder a secret can be created in,
	// because with one folder level there is nothing below a root but its
	// secrets.
	if p.AllowsWithin("personal/aws") {
		t.Error("AllowsWithin(personal/aws) = true; a root has no sub-folders")
	}
	if !p.AllowsWithin("personal") {
		t.Error("AllowsWithin(personal) = false; a root hosts new secrets")
	}
}

// A root deeper than one segment is not a folder in this key space — it names
// a secret. The policy drops it rather than admitting a subtree that cannot
// exist, matching what config load refuses outright, so the two can never
// disagree about what is editable.
func TestEditPolicyDropsAMultiSegmentRoot(t *testing.T) {
	p := kvpath.NewEditPolicy([]string{"scratch/notes"}, nil)
	if p.Enabled() {
		t.Errorf("Enabled() = true with only a multi-segment root; roots = %v", p.Roots())
	}
	for _, refused := range []string{"scratch/notes/todo", "scratch/notes", "scratch/x"} {
		if p.Allows(refused) {
			t.Errorf("Allows(%q) = true under a dropped root", refused)
		}
	}
}

// A backslash-bearing root is dropped by the policy exactly as config load
// refuses it, so the two agree here as they do on depth.
func TestEditPolicyDropsABackslashRoot(t *testing.T) {
	p := kvpath.NewEditPolicy([]string{`personal\notes`}, nil)
	if p.Enabled() {
		t.Errorf("Enabled() = true with only a backslash root; roots = %v", p.Roots())
	}
	if p.Allows(`personal\notes/token`) {
		t.Error("a backslash root granted editing")
	}
}

// CleanEditableRoot is the one definition of the root rule, shared by config
// load (which reports) and NewEditPolicy (which drops).
func TestCleanEditableRoot(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		wantErr  error
	}{
		{in: "personal", want: "personal"},
		{in: "/personal/", want: "personal"},
		{in: "scratch/notes", wantErr: kvpath.ErrRootDepth},
		// A backslash is an ordinary character in a Vault path segment, so
		// without this it passes the single-segment test and names a real,
		// writable folder literally called "personal\notes".
		{in: `personal\notes`, wantErr: kvpath.ErrRootSeparator},
		{in: `a\b\c`, wantErr: kvpath.ErrRootSeparator},
		{in: "a/b/c", wantErr: kvpath.ErrRootDepth},
		{in: "", wantErr: kvpath.ErrNotEditable},
		{in: "/", wantErr: kvpath.ErrNotEditable},
		{in: "personal/../gh", wantErr: kvpath.ErrInvalidName},
	} {
		got, err := kvpath.CleanEditableRoot(tc.in)
		if tc.wantErr != nil {
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("CleanEditableRoot(%q) = (%q, %v), want %v", tc.in, got, err, tc.wantErr)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("CleanEditableRoot(%q) = (%q, %v), want (%q, nil)", tc.in, got, err, tc.want)
		}
	}
}

// A prefix match on the raw string would admit "personalish/x" under the root
// "personal"; the separator in the comparison is what stops it. Pinned
// separately because it is the failure a reviewer cannot see by reading the
// happy path.
func TestEditPolicyDoesNotMatchPartialSegment(t *testing.T) {
	p := kvpath.NewEditPolicy([]string{"personal"}, nil)
	if p.Allows("personalish/token") {
		t.Error("personalish/token is editable under root personal")
	}
	if p.AllowsWithin("personalish") {
		t.Error("personalish is within root personal")
	}
}

// Two roots where one is a prefix of the other must stay independent: the
// separator in the comparison is what keeps "personal" from swallowing
// "personalish", and each must admit its own children and no more.
func TestEditPolicyKeepsPrefixOverlappingRootsApart(t *testing.T) {
	p := kvpath.NewEditPolicy([]string{"personal", "personalish"}, nil)
	for _, ok := range []string{"personal/token", "personalish/token"} {
		if !p.Allows(ok) {
			t.Errorf("Allows(%q) = false, want true", ok)
		}
	}
	for _, refused := range []string{"personal", "personalish", "personalish/a/b"} {
		if p.Allows(refused) {
			t.Errorf("Allows(%q) = true, want false", refused)
		}
	}
	if !p.AllowsWithin("personalish") || !p.AllowsWithin("personal") {
		t.Error("a root that prefixes another is not itself within the policy")
	}
}

func TestEditPolicyRefusesManagedPaths(t *testing.T) {
	p := kvpath.NewEditPolicy([]string{"personal"}, []string{"personal/gh", "gh"})

	if _, err := p.Allow("personal/gh"); !errors.Is(err, kvpath.ErrManaged) {
		t.Errorf("Allow(personal/gh) = %v, want ErrManaged", err)
	}
	// A managed path shields only *itself*: an enrolment writes one secret,
	// and its siblings in the same folder stay ordinary editable space. This
	// is the positive case the rule needs — without it, a policy that shielded
	// a managed path's whole root would pass every other assertion here.
	if _, err := p.Allow("personal/token"); err != nil {
		t.Errorf("Allow(personal/token) = %v, want nil (a sibling of a managed path is editable)", err)
	}
	// There is nothing *below* a managed path to shield, since the key space
	// is one folder deep — a child of a secret is refused for depth, not
	// because the enrolment reaches down into it.
	if _, err := p.Allow("personal/gh/extra"); !errors.Is(err, kvpath.ErrSecretDepth) {
		t.Errorf("Allow(personal/gh/extra) = %v, want ErrSecretDepth", err)
	}
	// A managed path outside every root is refused for the ordinary reason,
	// so the two rules cannot mask each other.
	if _, err := p.Allow("gh"); !errors.Is(err, kvpath.ErrNotEditable) {
		t.Errorf("Allow(gh) = %v, want ErrNotEditable", err)
	}
}

func TestEditPolicyZeroValuePermitsNothing(t *testing.T) {
	var p kvpath.EditPolicy
	if p.Enabled() {
		t.Error("zero EditPolicy reports Enabled")
	}
	if p.Allows("personal/token") || p.AllowsWithin("personal") {
		t.Error("zero EditPolicy permits a path")
	}
	if _, err := p.Allow("personal/token"); !errors.Is(err, kvpath.ErrNotEditable) {
		t.Errorf("Allow on zero policy = %v, want ErrNotEditable", err)
	}
}

// An unconfigured policy must be indistinguishable from one whose roots were
// all unusable, so a typo in config cannot silently open the whole key space.
func TestEditPolicyDropsUnusableRoots(t *testing.T) {
	p := kvpath.NewEditPolicy([]string{"", "/", "..", "a//b"}, nil)
	if p.Enabled() {
		t.Errorf("Enabled with roots %v, want none usable", p.Roots())
	}
}

func TestEditPolicyNormalisesAndDeduplicatesRoots(t *testing.T) {
	p := kvpath.NewEditPolicy([]string{"/personal/", "personal", "scratch"}, nil)
	got := p.Roots()
	want := []string{"personal", "scratch"}
	if len(got) != len(want) {
		t.Fatalf("Roots() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Roots() = %v, want %v", got, want)
		}
	}
	// Roots() must hand back a copy: a caller mutating it (a template
	// sorting for display, say) must not rewrite the policy.
	got[0] = "clobbered"
	if p.Roots()[0] != "personal" {
		t.Error("Roots() aliases the policy's own slice")
	}
}

// AllowsWithin is the weaker question the folder page asks: a root is not an
// editable secret but secrets may certainly be created inside it. With the key
// space one folder deep, a root is also the *only* place they can be created —
// there is nothing below it but its secrets.
func TestEditPolicyAllowsWithin(t *testing.T) {
	p := kvpath.NewEditPolicy([]string{"personal"}, nil)
	if !p.AllowsWithin("personal") {
		t.Error("AllowsWithin(personal) = false, want true")
	}
	for _, out := range []string{"", "gh", "other", "personal/aws"} {
		if p.AllowsWithin(out) {
			t.Errorf("AllowsWithin(%q) = true, want false", out)
		}
	}
}

func TestEditPolicyRejectsTraversal(t *testing.T) {
	p := kvpath.NewEditPolicy([]string{"personal"}, nil)
	for _, bad := range []string{"personal/../gh", "personal/./x", "personal//x", "personal/x\x00y"} {
		if _, err := p.Allow(bad); !errors.Is(err, kvpath.ErrInvalidName) {
			t.Errorf("Allow(%q) = %v, want ErrInvalidName", bad, err)
		}
	}
}
