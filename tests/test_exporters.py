import yaml

from finance_redteam.exporters import export_jsonl, load_jsonl
from finance_redteam.local_generator import seeds_to_records
from finance_redteam.promptfoo_exporter import export_promptfoo
from finance_redteam.seed_prompts import build_seed_prompts
from finance_redteam.taxonomy import build_default_taxonomy


def _records():
    categories = build_default_taxonomy()
    seeds = build_seed_prompts(categories[:1], per_category=1)
    return seeds_to_records(seeds, categories)


def test_jsonl_export(tmp_path):
    path = tmp_path / "attacks.jsonl"
    export_jsonl(_records(), path)
    loaded = load_jsonl(path)
    assert len(loaded) == 1


def test_promptfoo_yaml_export(tmp_path):
    path = tmp_path / "promptfoo.yaml"
    export_promptfoo(_records(), path)
    data = yaml.safe_load(path.read_text())
    assert data["tests"][0]["vars"]["attack_id"]
    assert data["providers"][0] == "file://../../providers/gemini_rest_provider.js"
