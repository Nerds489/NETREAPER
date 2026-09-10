"""Tool chaining system for NETREAPER.

This module provides a declarative tool chaining system that enables
piping output from one security tool to the next.

Example:
    from netreaper.chaining import (
        ChainDefinition,
        ChainStep,
        DataBinding,
        ChainExecutor,
        chain_registry,
    )

    # Define a simple chain
    chain = ChainDefinition(
        id="my_chain",
        name="My Custom Chain",
        description="Example chain",
        steps=[
            ChainStep(
                id="scan",
                tool="nmap",
                options={"ports": "1-1000"},
            ),
            ChainStep(
                id="enumerate",
                tool="nmap",
                target_binding=DataBinding(
                    source_step="scan",
                    source_path="hosts[*].ip",
                    target_option="target",
                    transform=lambda ips: ",".join(ips),
                ),
                options={"service_detection": True},
                depends_on=["scan"],
            ),
        ],
    )

    # Register and execute
    chain_registry.register(chain)
    executor = ChainExecutor()
    result = await executor.execute(chain, target="192.168.1.0/24")
"""

from netreaper.chaining.models import (
    ChainDefinition,
    ChainResult,
    ChainStep,
    Condition,
    DataBinding,
    OnErrorBehavior,
    StepResult,
    StepStatus,
)
from netreaper.chaining.executor import ChainExecutor
from netreaper.chaining.registry import ChainRegistry, chain_registry
from netreaper.chaining.paths import resolve_path, format_path
from netreaper.chaining.transforms import (
    TRANSFORMS,
    apply_transform,
    get_transform,
    flatten_ips,
    filter_open_ports,
    extract_services,
    extract_ports,
    first,
    last,
    join,
    unique,
    to_cidr,
    to_port_list,
)

__all__ = [
    # Models
    "ChainDefinition",
    "ChainResult",
    "ChainStep",
    "Condition",
    "DataBinding",
    "OnErrorBehavior",
    "StepResult",
    "StepStatus",
    # Executor
    "ChainExecutor",
    # Registry
    "ChainRegistry",
    "chain_registry",
    # Path utilities
    "resolve_path",
    "format_path",
    # Transforms
    "TRANSFORMS",
    "apply_transform",
    "get_transform",
    "flatten_ips",
    "filter_open_ports",
    "extract_services",
    "extract_ports",
    "first",
    "last",
    "join",
    "unique",
    "to_cidr",
    "to_port_list",
]


def initialize_chains() -> None:
    """Initialize the chaining system with built-in chains.

    Call this at application startup to register all built-in chains.
    """
    from netreaper.chaining.builtin import register_all_builtin_chains
    register_all_builtin_chains()
