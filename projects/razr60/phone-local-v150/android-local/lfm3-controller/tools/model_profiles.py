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
}

def profile(name=DEFAULT_PROFILE):
    if not isinstance(name, str) or name not in PROFILES:
        raise ValueError("unknown pinned model_profile")
    return dict(PROFILES[name])
