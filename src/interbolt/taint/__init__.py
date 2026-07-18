"""The taint carrier, propagation, and ingress-labeling primitives."""

from __future__ import annotations

from interbolt.taint.carriers import LabeledValue as LabeledValue
from interbolt.taint.carriers import Tainted as Tainted
from interbolt.taint.carriers import TaintedBytes as TaintedBytes
from interbolt.taint.carriers import _fresh_label as _fresh_label
from interbolt.taint.carriers import _merge_labels as _merge_labels
from interbolt.taint.endorse import endorse as endorse
from interbolt.taint.ingress import taint as taint
from interbolt.taint.ingress import track_model_call as track_model_call
from interbolt.taint.runstate import clear_run_ingress as clear_run_ingress
from interbolt.taint.runstate import (
    install_endorsement_emitter as install_endorsement_emitter,
)
from interbolt.taint.runstate import install_taint_observer as install_taint_observer
from interbolt.taint.runstate import run_ingress_sources as run_ingress_sources
from interbolt.taint.walk import collect_labels as collect_labels
from interbolt.taint.walk import unwrap as unwrap
