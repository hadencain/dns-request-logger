from src.analyzer import Analyzer, run_heuristics, shannon_entropy


# --- Heuristic unit tests ---

def test_entropy_low_for_normal_word():
    assert shannon_entropy("google") < 3.5


def test_entropy_high_for_random_string():
    # "xk3p9zq2mf" has 10 all-unique chars; max entropy = log2(10) ≈ 3.32
    # threshold is 3.2 so this correctly signals high entropy
    assert shannon_entropy("xk3p9zq2mf") > 3.2


def test_tld_flag_suspicious():
    flags = run_heuristics("malware.xyz")
    assert "TLD" in flags


def test_tld_flag_clean():
    flags = run_heuristics("google.com")
    assert "TLD" not in flags


def test_ent_flag_random_subdomain():
    flags = run_heuristics("xk3p9zq2mf.example.com")
    assert "ENT" in flags


def test_ent_flag_clean_subdomain():
    flags = run_heuristics("fonts.googleapis.com")
    assert "ENT" not in flags


def test_sub_flag_deep_labels():
    flags = run_heuristics("a.b.c.d.e.example.com")
    assert "SUB" in flags


def test_sub_flag_shallow_labels():
    flags = run_heuristics("sub.example.com")
    assert "SUB" not in flags


def test_no_flags_for_clean_domain():
    flags = run_heuristics("fonts.googleapis.com")
    assert flags == set()


# --- Analyzer state tests ---

def _event(domain="example.com", qtype="A", pid=1):
    return {"domain": domain, "query_type": qtype, "pid": pid, "timestamp": "2026-01-01T00:00:00Z"}


def test_total_increments():
    a = Analyzer()
    a.process(_event())
    a.process(_event())
    assert a.snapshot()["total"] == 2


def test_domain_count():
    a = Analyzer()
    a.process(_event("a.com"))
    a.process(_event("a.com"))
    a.process(_event("b.com"))
    snap = a.snapshot()
    assert snap["domains"]["a.com"] == 2
    assert snap["domains"]["b.com"] == 1


def test_new_flag_removed_on_second_query():
    a = Analyzer()
    a.process(_event("a.com"))
    assert "NEW" in a.snapshot()["meta"]["a.com"]["flags"]
    a.process(_event("a.com"))
    assert "NEW" not in a.snapshot()["meta"]["a.com"]["flags"]


def test_query_types_collected():
    a = Analyzer()
    a.process(_event("a.com", qtype="A"))
    a.process(_event("a.com", qtype="AAAA"))
    snap = a.snapshot()
    assert {"A", "AAAA"} == snap["meta"]["a.com"]["query_types"]


def test_heuristics_run_once_per_domain():
    a = Analyzer()
    a.process(_event("malware.xyz"))
    a.process(_event("malware.xyz"))
    snap = a.snapshot()
    assert "TLD" in snap["meta"]["malware.xyz"]["flags"]


def test_dropped_increments():
    a = Analyzer()
    a.increment_dropped()
    a.increment_dropped()
    assert a.snapshot()["dropped"] == 2


def test_snapshot_is_independent_copy():
    a = Analyzer()
    a.process(_event("a.com"))
    snap1 = a.snapshot()
    a.process(_event("a.com"))
    snap2 = a.snapshot()
    assert snap1["domains"]["a.com"] == 1
    assert snap2["domains"]["a.com"] == 2
