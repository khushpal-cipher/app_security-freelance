import yaml
from pydantic import ValidationError

from app.models import EndpointSpec, EndpointsFile


class SpecError(Exception):
    pass


def load_endpoints(yaml_text: str) -> list[EndpointSpec]:
    """Parse and schema-validate a YAML endpoint spec. Raises SpecError with a clear message."""
    try:
        raw = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        raise SpecError(f"Invalid YAML: {e}") from e
    if raw is None:
        raise SpecError("Endpoint spec is empty.")
    try:
        parsed = EndpointsFile.model_validate(raw)
    except ValidationError as e:
        raise SpecError(f"Endpoint spec failed validation: {e}") from e
    if not parsed.endpoints:
        raise SpecError("Endpoint spec has no endpoints listed.")
    return parsed.endpoints
