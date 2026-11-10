"""Closed model artifact allowlist; no device access or model download."""
DEFAULT_PROFILE = "lfm3-1.7b-qad-q4_0"
LLAMA_COMMIT = "19cce6919992fdffd92e0ac152caaf1e2b8f254e"
PROFILES = {
    DEFAULT_PROFILE: {"file": "LFM3-1.7B-QAD-Q4_0.gguf", "bytes": 1049615680,
        "sha256": "43a7d09a0e9cba91b63eb7052488b9564569bddfd65754d2e426465e572a7452", "architecture": "lfm3", "exact": False},
    "minicpm5-2b-q4_k_m": {"file": "MiniCPM5-2B-Q4_K_M.gguf", "bytes": 1561318368,
        "sha256": "ec2d5801640099e97d8d7e8003ad4d81f336e757811f03a26173dddf386602fd", "architecture": "llama", "exact": True},
    "spark-x2.6-4b-q4_k_m": {"file": "Spark-X2.6-4B-Q4_K_M.gguf", "bytes": 3543441312,
        "sha256": "91cb2811aebb47ac916aa619d27d4cdd7f4143106b7917accb8ead4cd7f5cbd9", "architecture": "spark2_5", "exact": True},
    "gemma4-e4b-qat-q4_0": {"file": "gemma-4-E4B_q4_0-it.gguf", "bytes": 5154941280,
        "sha256": "676c35070db6dbe52f93e9c864ee0fba4eddea94b9c875d9cb10daff453fbaee", "architecture": "gemma4", "exact": True},
    "gemma4-e2b-qat-q4_0": {"file": "gemma-4-E2B_q4_0-it.gguf", "bytes": 3349516256,
        "sha256": "fa401b55b07ee70a54c6dae3903c783a6e65064312529ea57175cb5f8dec6634", "architecture": "gemma4", "exact": True},
    "nemotron-3.5-bolt-e4b-q4_k_m": {"file": "Nemotron-3.5-Bolt-E4B-Q4_K_M.gguf", "bytes": 6180446208,
        "sha256": "c8af2b8aea10a690a1d9491db744a9446660173cb38fc489612b556615a69612", "architecture": "gemma4", "exact": True},
    "lfm2.5-8b-a1b-q4_0": {"file": "LFM2.5-8B-A1B-Q4_0.gguf", "bytes": 4844678368,
        "sha256": "48ed1465d761311b2fd57b7fb46cf969a20b3a8281945b04e10f52bd1609e715", "architecture": "lfm2moe", "exact": True},
    "qwen3.5-4b-q4_0": {"file": "Qwen3.5-4B-Q4_0.gguf", "bytes": 2583221408,
        "sha256": "298fcb5fe7a77ccc79745ae24751560c5ac56874caff4bb39b1f2055bd72b8bb", "architecture": "qwen35", "exact": True},
    "qwen3.5-9b-q4_0": {"file": "Qwen3.5-9B-Q4_0.gguf", "bytes": 5379417312,
        "sha256": "17670346b4260ddcb0173965145155885024f3c9a4a24389a3370751edbcde24", "architecture": "qwen35", "exact": True},
    "bonsai2-9b-q2_0": {"file": "Ternary-Bonsai-2-9B-Q2_0.gguf", "bytes": 2556640128,
        "sha256": "1f884aa56aacd2bbbb2e4b7abaead2b1102b74a9c75a23fc33dab916813a384d", "architecture": "qwen35", "exact": True},
    "orvena-4b-q4_k_m": {"file": "Orvena-4B.Q4_K_M.gguf", "bytes": 2783447904,
        "sha256": "c5d6df6e9a0828fa3068dfc6f6ca2ff6c4d950adc7e60e4b7202ece61595aa57", "architecture": "qwen35", "exact": True},
}

def profile(name=DEFAULT_PROFILE):
    if not isinstance(name, str) or name not in PROFILES:
        raise ValueError("unknown pinned model_profile")
    return dict(PROFILES[name])
