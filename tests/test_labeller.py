import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = ROOT / "benchmarks" / "configs"


def load_config(filename):
    path = CONFIG_DIR / filename

    with open(path, "r") as file:
        return json.load(file)


def test_memcmp_config():

    config = load_config("memcmp.json")

    assert config["function"] == "secret_memcmp"

    assert "a" in config["secret_parameters"]
    assert "b" in config["secret_parameters"]

    assert "n" in config["public_parameters"]


def test_aes_sbox_config():

    config = load_config("aes_sbox.json")

    assert config["function"] == "aes_sbox"

    assert "input" in config["secret_parameters"]


def test_mod_exp_config():

    config = load_config("mod_exp.json")

    assert config["function"] == "mod_exp"

    assert "secret_exp" in config["secret_parameters"]

    assert "base" in config["public_parameters"]
    assert "mod" in config["public_parameters"]
