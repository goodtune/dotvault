package clientcert

import "testing"

func TestPairCombinedAddsSeparatorNewline(t *testing.T) {
	p := &Pair{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY\n")}
	if got := string(p.Combined()); got != "CERT\nKEY\n" {
		t.Fatalf("Combined = %q", got)
	}
	p = &Pair{CertPEM: []byte("CERT\n"), KeyPEM: []byte("KEY\n")}
	if got := string(p.Combined()); got != "CERT\nKEY\n" {
		t.Fatalf("Combined = %q", got)
	}
}

func TestLeafDERSkipsNonCertificateBlocks(t *testing.T) {
	if LeafDER([]byte("not pem")) != nil {
		t.Error("LeafDER of non-PEM input is not nil")
	}
	in := []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n")
	if got := LeafDER(in); string(got) != "\x01\x02\x03" {
		t.Errorf("LeafDER = %x, want 010203", got)
	}
}
