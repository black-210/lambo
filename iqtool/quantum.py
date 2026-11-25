from __future__ import annotations

import cmath
import math
from typing import Any

GATES: dict[str, tuple[tuple[complex, complex], tuple[complex, complex]]] = {
    "H": (
        (1 / math.sqrt(2), 1 / math.sqrt(2)),
        (1 / math.sqrt(2), -1 / math.sqrt(2)),
    ),
    "X": ((0, 1), (1, 0)),
    "Y": ((0, -1j), (1j, 0)),
    "Z": ((1, 0), (0, -1)),
    "S": ((1, 0), (0, 1j)),
    "T": ((1, 0), (0, cmath.exp(1j * math.pi / 4))),
}


def simulate_qubit(
    gates: list[str] | tuple[str, ...] = (),
    theta: float = 0.0,
    phi: float = 0.0,
) -> dict[str, Any]:
    if not math.isfinite(theta) or not math.isfinite(phi):
        raise ValueError("Initial-state angles must be finite numbers.")

    state = (
        complex(math.cos(theta / 2), 0),
        cmath.exp(complex(0, phi)) * math.sin(theta / 2),
    )
    normalized_gates = [gate.upper() for gate in gates]
    for gate in normalized_gates:
        if gate not in GATES:
            raise ValueError(f"Unsupported gate {gate!r}; choose from {', '.join(GATES)}.")
        matrix = GATES[gate]
        state = (
            matrix[0][0] * state[0] + matrix[0][1] * state[1],
            matrix[1][0] * state[0] + matrix[1][1] * state[1],
        )

    norm = math.sqrt(abs(state[0]) ** 2 + abs(state[1]) ** 2)
    if not math.isfinite(norm) or norm == 0:
        raise ValueError("Simulation produced an invalid state vector.")
    state = (state[0] / norm, state[1] / norm)

    def serialize_amplitude(value: complex) -> dict[str, float]:
        return {"real": float(value.real), "imag": float(value.imag)}

    probabilities = (float(abs(state[0]) ** 2), float(abs(state[1]) ** 2))
    return {
        "schema_version": 1,
        "analysis": "educational_single_qubit_state_vector",
        "gates": normalized_gates,
        "state": {
            "0": serialize_amplitude(state[0]),
            "1": serialize_amplitude(state[1]),
        },
        "probabilities": {"0": probabilities[0], "1": probabilities[1]},
        "limitations": [
            "This is a small idealized one-qubit state-vector simulation.",
            "It does not model noise, hardware, many-body systems, or prove physical properties.",
        ],
    }
