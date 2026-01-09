"""Data quality metrics using DeepEval's G-Eval."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from deepeval.metrics import GEval
from deepeval.test_case import LLMTestCaseParams

if TYPE_CHECKING:
    from deepeval.models import DeepEvalBaseLLM


def create_data_plausibility_metric(
    network: str = "mainnet",
    model: "DeepEvalBaseLLM | str | None" = None,
) -> GEval:
    """Create a metric to evaluate data plausibility for Ethereum data.

    Args:
        network: The Ethereum network being queried (mainnet, holesky, etc.)
        model: LLM model to use for evaluation (default: gpt-4o)

    Returns:
        A GEval metric configured for data plausibility checking.
    """
    kwargs = {"model": model} if model else {}
    current_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return GEval(
        name="DataPlausibility",
        threshold=0.7,
        **kwargs,
        evaluation_steps=[
            f"IMPORTANT: The current date is {current_date}. Use this when evaluating timestamps.",
            f"The query targets the {network} Ethereum network.",
            "Numeric values are in reasonable ranges:",
            "  - Block counts for 24h should be approximately 7200 for mainnet (12s block time)",
            "  - Slot numbers should be positive and less than current slot",
            "  - Epoch numbers should be positive",
            "  - Gas values should be positive integers",
            "If output references consensus clients, they are real Ethereum clients:",
            "  - Valid consensus clients: Prysm, Lighthouse, Teku, Nimbus, Lodestar",
            "If output references execution clients, they are real Ethereum clients:",
            "  - Valid execution clients: Geth, Nethermind, Besu, Erigon, Reth",
            f"Timestamps, if present, are reasonable (on or before {current_date}, not too far in the past)",
            "Percentages are between 0 and 100",
            "The response acknowledges when data is unavailable rather than hallucinating values",
        ],
        evaluation_params=[LLMTestCaseParams.INPUT, LLMTestCaseParams.ACTUAL_OUTPUT],
    )


def create_sql_correctness_metric(
    model: "DeepEvalBaseLLM | str | None" = None,
) -> GEval:
    """Create a metric to evaluate SQL/ClickHouse query correctness.

    Args:
        model: LLM model to use for evaluation (default: gpt-4o)

    Returns:
        A GEval metric configured for SQL correctness checking.
    """
    kwargs = {"model": model} if model else {}
    return GEval(
        name="SQLCorrectness",
        threshold=0.8,
        **kwargs,
        evaluation_steps=[
            "The SQL query is syntactically correct for ClickHouse",
            "Table names referenced exist in the xatu schema (beacon_api_*, canonical_*, etc.)",
            "Column names are valid for the referenced tables",
            "Time range filters use appropriate ClickHouse date/time functions",
            "The query uses appropriate aggregation functions (count, sum, avg, etc.)",
            "JOIN conditions are logically correct",
            "GROUP BY clauses include all non-aggregated columns in SELECT",
            "ORDER BY references valid columns or aliases",
            "LIMIT is used appropriately for large result sets",
            "The query avoids common pitfalls like Cartesian products",
        ],
        evaluation_params=[LLMTestCaseParams.INPUT, LLMTestCaseParams.ACTUAL_OUTPUT],
    )


def create_network_awareness_metric(
    model: "DeepEvalBaseLLM | str | None" = None,
) -> GEval:
    """Create a metric to evaluate network-specific awareness.

    Args:
        model: LLM model to use for evaluation (default: gpt-4o)

    Returns:
        A GEval metric configured for network awareness checking.
    """
    kwargs = {"model": model} if model else {}
    return GEval(
        name="NetworkAwareness",
        threshold=0.8,
        **kwargs,
        evaluation_steps=[
            "The response correctly identifies or infers the target network",
            "Network-specific parameters are used correctly:",
            "  - Mainnet: ~12s block time, specific genesis time",
            "  - Holesky: test network parameters",
            "  - Sepolia: test network parameters",
            "The response does not confuse networks or mix network-specific data",
            "When querying multiple networks, results are clearly distinguished",
        ],
        evaluation_params=[LLMTestCaseParams.INPUT, LLMTestCaseParams.ACTUAL_OUTPUT],
    )
