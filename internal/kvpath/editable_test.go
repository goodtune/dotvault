package kvpath_test

import (
	"errors"
	"testing"

	"github.com/goodtune/dotvault/internal/kvpath"
)

func TestEditPolicyStrictSubtree(t *testing.T) {
	p := kvpath.NewEditPolicy([]string{"personal", "scratch/notes"}, nil)

	for _, ok := range []string{
		"personal/token",
		"personal/aws/dev",
		"scratch/notes/todo",
		"scratch/notes/a/b/c",
	} {
		if clean, err := p.Allow(ok); err != nil {
			t.Errorf("Allow(%q) = %v, want nil", ok, err)
		} else if clean != ok {
			t.Errorf("Allow(%q) cleaned to %q", ok, clean)
		}
	}

	// The root of the key space, the roots themselves, and anything outside
	// them are all refused. A root naming a subtree must not make the secret
	// of the same name — a direct child of the key-space root — editable.
	for _, refused := range []string{
		"",
		"personal",
		"scratch",
		"scratch/notes",
		"gh",
		"personalish/token",
		"other/personal/token",
	} {
		if _, err := p.Allow(refused); !errors.Is(err, kvpath.ErrNotEditable) {
			t.Errorf("Allow(%q) = %v, want ErrNotEditable", refused, err)
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

func TestEditPolicyRefusesManagedPaths(t *testing.T) {
	p := kvpath.NewEditPolicy([]string{"personal"}, []string{"personal/gh", "gh"})

	if _, err := p.Allow("personal/gh"); !errors.Is(err, kvpath.ErrManaged) {
		t.Errorf("Allow(personal/gh) = %v, want ErrManaged", err)
	}
	// A managed path shields only itself: an enrolment writes one secret, not
	// a subtree, so a child of it is ordinary editable space.
	if _, err := p.Allow("personal/gh/extra"); err != nil {
		t.Errorf("Allow(personal/gh/extra) = %v, want nil", err)
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
// editable secret but secrets may certainly be created inside it.
func TestEditPolicyAllowsWithin(t *testing.T) {
	p := kvpath.NewEditPolicy([]string{"personal"}, nil)
	for _, in := range []string{"personal", "personal/aws"} {
		if !p.AllowsWithin(in) {
			t.Errorf("AllowsWithin(%q) = false, want true", in)
		}
	}
	for _, out := range []string{"", "gh", "other"} {
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
