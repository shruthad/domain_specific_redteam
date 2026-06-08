from __future__ import annotations

import logging
from pathlib import Path

import typer

from .builder import build_records_from_config, export_build_result
from .config import BenchmarkConfig, DEFAULT_CONFIG_PATH, OutputConfig, load_benchmark_config
from .deduplicator import deduplicate_records
from .deepteam_adapter import DeepTeamExpansionConfig, generate_deepteam_variants
from .exporters import export_jsonl, load_jsonl
from .garak_adapter import run_garak_scan
from .local_generator import generate_local_variants, seeds_to_records
from .normalizer import normalize_record
from .promptfoo_exporter import export_promptfoo
from .seed_prompts import DEFAULT_SEEDS_PATH, build_seed_prompts, load_seed_prompts, write_seed_prompts
from .taxonomy import DEFAULT_FRAMEWORK_MAPPINGS_PATH, DEFAULT_TAXONOMY_PATH, load_taxonomy, write_framework_mappings, write_taxonomy
from .validator import validate_records

app = typer.Typer(help="Build a static finance-domain LLM red-team benchmark.")


def _setup_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")


def _build_records(
    min_per_category: int,
    max_per_category: int,
    use_deepteam: bool,
    use_garak: bool,
) -> list:
    config = BenchmarkConfig(
        min_per_category=min_per_category,
        max_per_category=max_per_category,
        use_deepteam=use_deepteam,
        use_garak=use_garak,
    )
    result = build_records_from_config(config)
    return result.records


@app.command()
def build(
    output: Path = typer.Option(Path("data/exports/finance_redteam_attacks.jsonl")),
    promptfoo_output: Path = typer.Option(Path("data/exports/promptfoo_tests.yaml")),
    min_per_category: int = typer.Option(5),
    max_per_category: int = typer.Option(10),
    use_deepteam: bool = typer.Option(False),
    use_garak: bool = typer.Option(False),
) -> None:
    _setup_logging()
    config = BenchmarkConfig(
        min_per_category=min_per_category,
        max_per_category=max_per_category,
        use_deepteam=use_deepteam,
        use_garak=use_garak,
        output=OutputConfig(jsonl=output, promptfoo_yaml=promptfoo_output),
    )
    result = build_records_from_config(config)
    for warning in result.validation.review_warnings:
        logging.warning("Review warning: %s", warning)
    if not result.validation.valid:
        for error in result.validation.errors:
            logging.error(error)
        raise typer.Exit(code=1)
    export_build_result(result, config)
    typer.echo(f"Exported {len(result.records)} records to {output}")
    typer.echo(f"Exported Promptfoo config to {promptfoo_output}")
    typer.echo(f"Wrote run metadata to {config.output.run_metadata_json}")


@app.command("build-from-config")
def build_from_config(config_path: Path = typer.Argument(DEFAULT_CONFIG_PATH)) -> None:
    _setup_logging()
    config = load_benchmark_config(config_path)
    result = build_records_from_config(config)
    for warning in result.validation.review_warnings:
        logging.warning("Review warning: %s", warning)
    if not result.validation.valid:
        for error in result.validation.errors:
            logging.error(error)
        raise typer.Exit(code=1)
    export_build_result(result, config)
    typer.echo(f"Exported {len(result.records)} records to {config.output.jsonl}")
    typer.echo(f"Exported Promptfoo config to {config.output.promptfoo_yaml}")
    typer.echo(f"Wrote run metadata to {config.output.run_metadata_json}")


@app.command("generate-taxonomy")
def generate_taxonomy() -> None:
    write_taxonomy()
    write_framework_mappings()
    typer.echo(f"Wrote {DEFAULT_TAXONOMY_PATH} and {DEFAULT_FRAMEWORK_MAPPINGS_PATH}")


@app.command("generate-seeds")
def generate_seeds(per_category: int = 5) -> None:
    write_taxonomy()
    write_seed_prompts(per_category=per_category)
    typer.echo(f"Wrote {DEFAULT_SEEDS_PATH}")


@app.command("expand-deepteam")
def expand_deepteam(
    input_path: Path = Path("data/exports/finance_redteam_attacks.jsonl"),
    vulnerabilities: list[str] | None = typer.Option(None),
    attack_types: list[str] | None = typer.Option(None),
    max_seed_records: int = typer.Option(20),
    variants_per_seed: int = typer.Option(1),
) -> None:
    records = load_jsonl(input_path)
    variants = generate_deepteam_variants(
        records,
        expansion_config=DeepTeamExpansionConfig(
            vulnerabilities=vulnerabilities or [],
            attack_types=attack_types or [],
            max_seed_records=max_seed_records,
            variants_per_seed=variants_per_seed,
        ),
    )
    export_jsonl(variants, Path("data/generated/deepteam_variants.jsonl"))
    typer.echo(f"Wrote {len(variants)} DeepTeam variants")


@app.command("run-garak")
def run_garak(target_model: str | None = None) -> None:
    records = run_garak_scan(target_model)
    export_jsonl(records, Path("data/generated/garak_patterns.jsonl"))
    typer.echo(f"Wrote {len(records)} Garak-derived patterns")


@app.command("export-promptfoo")
def export_promptfoo_command(
    input_path: Path = Path("data/exports/finance_redteam_attacks.jsonl"),
    output_path: Path = Path("data/exports/promptfoo_tests.yaml"),
) -> None:
    records = load_jsonl(input_path)
    export_promptfoo(records, output_path)
    typer.echo(f"Wrote {output_path}")


@app.command("validate")
def validate(input_path: Path = Path("data/exports/finance_redteam_attacks.jsonl")) -> None:
    records = load_jsonl(input_path)
    result = validate_records(records)
    for warning in result.review_warnings:
        typer.echo(f"WARNING: {warning}")
    if not result.valid:
        for error in result.errors:
            typer.echo(f"ERROR: {error}")
        raise typer.Exit(code=1)
    typer.echo(f"Validated {len(records)} records")


if __name__ == "__main__":
    app()
