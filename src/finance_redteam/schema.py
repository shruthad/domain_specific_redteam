from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


AttackType = Literal[
    "direct_request",
    "roleplay",
    "authority_impersonation",
    "audit_pretext",
    "developer_override",
    "system_prompt_extraction",
    "policy_bypass",
    "encoding_obfuscation",
    "multi_turn_setup",
    "indirect_prompt_injection",
    "rag_exfiltration",
    "tool_misuse",
    "jailbreak",
    "data_extraction",
    "hypothetical_scenario",
    "translation_attack",
    "summarization_attack",
]

InteractionType = Literal["single_turn", "multi_turn"]
SourceType = Literal["seed", "deepteam", "garak", "local_template"]


class TaxonomyCategory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category_id: str
    name: str
    description: str
    finance_examples: list[str]
    owasp_mapping: list[str]
    mitre_atlas_mapping: list[str]
    nist_ai_rmf_mapping: list[str]
    severity: Literal["low", "medium", "high", "critical"]
    default_expected_behavior: str


class SeedPrompt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category_id: str
    attack_type: AttackType
    difficulty: int = Field(ge=1, le=5)
    prompt: str
    expected_behavior: str
    unsafe_success_criteria: str
    tags: list[str] = Field(default_factory=list)


class AttackRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_id: str
    domain: Literal["banking_finance"] = "banking_finance"
    risk_category: str
    risk_subcategory: str
    owasp_mapping: list[str]
    mitre_atlas_mapping: list[str]
    nist_ai_rmf_mapping: list[str]
    finance_domain_mapping: list[str]
    attack_type: AttackType
    interaction_type: InteractionType
    difficulty: int = Field(ge=1, le=5)
    source: SourceType
    prompt: str
    expected_behavior: str
    unsafe_success_criteria: str
    safe_response_guidance: str
    tags: list[str]
    created_by: str = "system"
    version: str = "1.0.0"
    dataset_version: str = "1.0.0"
    generation_run_id: str = "manual"
    generated_at: str = "manual"
    generator_config_hash: str = "manual"
    source_metadata: dict[str, Any] = Field(default_factory=dict)
    review_flags: list[str] = Field(default_factory=list)

    @field_validator(
        "attack_id",
        "risk_category",
        "risk_subcategory",
        "prompt",
        "expected_behavior",
        "unsafe_success_criteria",
        "safe_response_guidance",
    )
    @classmethod
    def non_empty_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("field must be non-empty")
        return value.strip()

    @field_validator(
        "owasp_mapping",
        "mitre_atlas_mapping",
        "nist_ai_rmf_mapping",
        "finance_domain_mapping",
        "tags",
    )
    @classmethod
    def non_empty_list(cls, value: list[str]) -> list[str]:
        cleaned = [item.strip() for item in value if item and item.strip()]
        if not cleaned:
            raise ValueError("list field must contain at least one value")
        return cleaned
