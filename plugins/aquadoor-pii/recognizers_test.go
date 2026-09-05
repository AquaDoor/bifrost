package aquadoorpii

import "testing"

// Anti-rubber-stamp (fail-closed discipline): each type asserts an independently-sourced VALID
// value → true, plus adversarial negatives — a perturbed CONTROL digit and a perturbed BODY digit
// must both be false (proves the checksum discriminates, not just the regex/length). Ported from
// the retired infra/presidio-ru/test_ru_checksums.py corpus.

func bump(s string, idx int) string {
	d := []byte(s)
	d[idx] = byte('0' + (int(d[idx]-'0')+1)%10)
	return string(d)
}

func TestValidateINN(t *testing.T) {
	valid10 := []string{"7830002293", "7707083893", "5009053292"}
	valid12 := []string{"500100732259"}
	for _, x := range valid10 {
		if !validateINN(x) {
			t.Errorf("valid inn10 rejected: %s", x)
		}
		if validateINN(bump(x, 9)) {
			t.Errorf("control-bump inn10 accepted: %s", x)
		}
		if validateINN(bump(x, 0)) {
			t.Errorf("body-bump inn10 accepted: %s", x)
		}
	}
	for _, x := range valid12 {
		if !validateINN(x) {
			t.Errorf("valid inn12 rejected: %s", x)
		}
		if validateINN(bump(x, 11)) {
			t.Errorf("control-bump inn12 accepted: %s", x)
		}
	}
	for _, bad := range []string{"1234567890", "0000000001", "783000229", "78300022933", "78300022x3", ""} {
		if validateINN(bad) {
			t.Errorf("malformed/random inn accepted: %q", bad)
		}
	}
}

func TestValidateOGRN(t *testing.T) {
	for _, x := range []string{"1027700132195", "1037739877295"} {
		if !validateOGRN(x) {
			t.Errorf("valid ogrn rejected: %s", x)
		}
		if validateOGRN(bump(x, 12)) {
			t.Errorf("control-bump ogrn accepted: %s", x)
		}
		if validateOGRN(bump(x, 3)) {
			t.Errorf("body-bump ogrn accepted: %s", x)
		}
	}
	for _, bad := range []string{"1234567890123", "102770013219", "10277001321955", "102770013219x"} {
		if validateOGRN(bad) {
			t.Errorf("malformed ogrn accepted: %q", bad)
		}
	}
}

func TestValidateOGRNIP(t *testing.T) {
	for _, x := range []string{"304500116000157", "316504000000013"} {
		if !validateOGRNIP(x) {
			t.Errorf("valid ogrnip rejected: %s", x)
		}
		if validateOGRNIP(bump(x, 14)) {
			t.Errorf("control-bump ogrnip accepted: %s", x)
		}
		if validateOGRNIP(bump(x, 5)) {
			t.Errorf("body-bump ogrnip accepted: %s", x)
		}
	}
	for _, bad := range []string{"123456789012345", "30450011600015", "3045001160001577"} {
		if validateOGRNIP(bad) {
			t.Errorf("malformed ogrnip accepted: %q", bad)
		}
	}
}

// recognize: end-to-end span detection + the INN-vs-passport overlap resolution.
func TestRecognize(t *testing.T) {
	// Valid INN with context → detected as RU_INN.
	rs := recognize("ИНН 7830002293", nil)
	if len(rs) != 1 || rs[0].EntityType != entityINN {
		t.Fatalf("expected one RU_INN, got %+v", rs)
	}

	// Random 10-digit, no passport context → nothing (INN checksum fails, passport not gated in).
	if rs := recognize("заказ 1234567890", nil); len(rs) != 0 {
		t.Fatalf("expected no detections for a random number, got %+v", rs)
	}

	// Phone (+7 distinctive shape) → detected without context.
	if rs := recognize("звони +7 999 123 45 67", nil); len(rs) != 1 || rs[0].EntityType != entityPhone {
		t.Fatalf("expected RU_PHONE, got %+v", rs)
	}

	// Passport requires context.
	if rs := recognize("номер 12 34 567890", nil); len(rs) != 0 {
		t.Fatalf("passport without context must not fire, got %+v", rs)
	}
	if rs := recognize("паспорт 12 34 567890", nil); len(rs) != 1 || rs[0].EntityType != entityPassport {
		t.Fatalf("passport with context must fire, got %+v", rs)
	}

	// entities filter restricts recognition.
	if rs := recognize("ИНН 7830002293", []string{entityPhone}); len(rs) != 0 {
		t.Fatalf("filter should exclude RU_INN, got %+v", rs)
	}
}

func TestAnonymize(t *testing.T) {
	text := "ИНН 7830002293 и телефон +7 999 123 45 67"
	got := anonymize(text, recognize(text, nil))
	want := "ИНН <RU_INN> и телефон <RU_PHONE>"
	if got != want {
		t.Errorf("anonymize:\n got=%q\nwant=%q", got, want)
	}
}
