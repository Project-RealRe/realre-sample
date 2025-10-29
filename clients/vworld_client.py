from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import urlopen

VWORLD_METADATA_PATH = (Path(__file__).resolve().parent / "vworld" / "vworld_url.json").resolve()
VWORLD_SEARCH_ENDPOINT = "https://api.vworld.kr/req/search"

_KOREAN_REQUIRED_FLAG = "필수"
_REQUEST_KEY = "요청 변수"
_URL_KEY = "URL"


class VWorldAPIError(RuntimeError):
    """Raised when a vworld API call fails."""


@dataclass(frozen=True)
class VWorldApiDefinition:
    name: str
    metadata: dict[str, Any]

    @property
    def endpoint(self) -> str:
        try:
            return self.metadata[_URL_KEY]
        except KeyError as exc:  # pragma: no cover - defensive, depends on external file integrity.
            raise VWorldAPIError(f"Metadata for '{self.name}' is missing the '{_URL_KEY}' field.") from exc

    @property
    def request_fields(self) -> dict[str, Any]:
        return self.metadata.get(_REQUEST_KEY, {})


def _load_api_catalog() -> dict[str, VWorldApiDefinition]:
    try:
        with VWORLD_METADATA_PATH.open(encoding="utf-8") as metadata_file:
            raw_catalog = json.load(metadata_file)
    except FileNotFoundError as exc:
        raise VWorldAPIError(f"Missing vworld metadata file: {VWORLD_METADATA_PATH}") from exc
    except json.JSONDecodeError as exc:
        raise VWorldAPIError(
            f"Failed to decode JSON metadata from {VWORLD_METADATA_PATH}: {exc.msg}"
        ) from exc

    return {name: VWorldApiDefinition(name, info) for name, info in raw_catalog.items()}


_API_CATALOG: dict[str, VWorldApiDefinition] | None = None


def _get_api_catalog() -> dict[str, VWorldApiDefinition]:
    global _API_CATALOG
    if _API_CATALOG is None:
        _API_CATALOG = _load_api_catalog()
    return _API_CATALOG


def get_vworld_api_info(api_name: str) -> VWorldApiDefinition:
    """
    Retrieve the metadata for the requested API.

    Parameters
    ----------
    api_name:
        The key stored in ``vworld_url.json`` (e.g. ``"getBuildingAge"``).
    """
    try:
        return _get_api_catalog()[api_name]
    except KeyError as exc:
        available = ", ".join(sorted(_get_api_catalog().keys()))
        raise VWorldAPIError(f"Unknown vworld API '{api_name}'. Available APIs: {available}") from exc


def _normalize_params(params: Mapping[str, Any] | None) -> dict[str, Any]:
    if not params:
        return {}

    normalized: dict[str, Any] = {}
    for key, value in params.items():
        if value is None:
            continue

        if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            sequence = [str(item) for item in value if item is not None]
            if sequence:
                normalized[key] = sequence
            continue

        normalized[key] = str(value)
    return normalized


def call_vworld_api(
    api_name: str,
    params: Mapping[str, Any] | None = None,
    *,
    api_key: str | None = None,
    domain: str | None = None,
    timeout: float = 10.0,
    parse_json: bool | None = None,
) -> Any:
    """
    Call one of the vworld OpenAPI endpoints using metadata from ``vworld_url.json``.

    Parameters
    ----------
    api_name:
        Entry key inside the metadata file (e.g. ``"getBuildingAge"``).
    params:
        Query parameters for the request. Values are stringified automatically.
    api_key:
        Optional API key. If provided, it is injected as the ``key`` query parameter
        unless it already exists in ``params``.
    domain:
        Optional domain parameter. Injected only when missing from ``params``.
    timeout:
        Socket timeout (seconds) passed to ``urllib.request.urlopen``.
    parse_json:
        Force JSON decoding of the response (``True``) or skip it (``False``).
        When ``None`` (default) the function attempts to decode JSON whenever the
        request includes ``format=json`` or the response advertises
        ``Content-Type: application/json``.

    Returns
    -------
    Any
        Parsed JSON data or the raw UTF-8 decoded response body.

    Raises
    ------
    VWorldAPIError
        If metadata is missing, required parameters are absent, or the HTTP request fails.
    ValueError
        If ``timeout`` is non-positive.
    """
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero.")

    api_info = get_vworld_api_info(api_name)
    request_fields = api_info.request_fields

    query_params = _normalize_params(params)
    if api_key is not None:
        query_params.setdefault("key", api_key)
    if domain is not None:
        query_params.setdefault("domain", domain)

    missing = [
        field_name
        for field_name, field_meta in request_fields.items()
        if field_meta.get("Required") == _KOREAN_REQUIRED_FLAG and field_name not in query_params
    ]
    if missing:
        raise VWorldAPIError(
            f"Missing required parameters for '{api_name}': {', '.join(sorted(missing))}"
        )

    encoded_params = urlencode(query_params, doseq=True)
    request_url = api_info.endpoint if not encoded_params else f"{api_info.endpoint}?{encoded_params}"

    try:
        with urlopen(request_url, timeout=timeout) as response:
            raw_body = response.read()
            content_type = response.headers.get("Content-Type", "")
    except HTTPError as exc:
        raise VWorldAPIError(
            f"vworld API '{api_name}' returned HTTP {exc.code}: {exc.reason}"
        ) from exc
    except URLError as exc:
        raise VWorldAPIError(f"Failed to reach vworld API '{api_name}': {exc.reason}") from exc

    if parse_json is None:
        format_param = str(query_params.get("format", "")).lower()
        parse_json = format_param == "json" or "application/json" in content_type.lower()

    if parse_json:
        try:
            return json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise VWorldAPIError(
                f"Unable to decode JSON response from '{api_name}': {exc.msg}"
            ) from exc

    return raw_body.decode("utf-8")


def search_address(
    address: str,
    *,
    api_key: str,
    category: str = "ROAD",
    crs: str = "EPSG:4326",
    size: int = 10,
    page: int = 1,
    bbox: Sequence[float] | None = None,
    domain: str | None = None,
    timeout: float = 10.0,
    format: str = "json",
    errorformat: str = "json",
) -> dict[str, Any]:
    """
    Query the vworld Search API for address information.

    Parameters
    ----------
    address:
        Human-readable address string (도로명 or 지번).
    api_key:
        vworld issued API key.
    category:
        Address category to search. Must be ``"ROAD"`` or ``"PARCEL"`` when ``type=address``.
    crs:
        Coordinate reference system to receive results in (e.g. ``"EPSG:4326"``).
    size:
        Number of results to request (1-1000).
    page:
        Page number to request (>=1).
    bbox:
        Optional bounding box (minx, miny, maxx, maxy) to spatially constrain the search.
    domain:
        Optional domain parameter to include in the request.
    timeout:
        Socket timeout (seconds) passed to ``urllib.request.urlopen``.
    format:
        Response format requested from the API. Only ``"json"`` is supported by this helper.
    errorformat:
        Error response format. Only ``"json"`` is supported by this helper.

    Returns
    -------
    dict[str, Any]
        Parsed JSON ``response`` block from the Search API.

    Raises
    ------
    ValueError
        If arguments are malformed (e.g. empty address, invalid size/page, unsupported category).
    VWorldAPIError
        If the API request fails or returns a non-JSON payload.
    """
    if not address or not address.strip():
        raise ValueError("address must be a non-empty string.")
    if not api_key or not api_key.strip():
        raise ValueError("api_key must be provided.")
    if size < 1 or size > 1000:
        raise ValueError("size must be between 1 and 1000.")
    if page < 1:
        raise ValueError("page must be greater than or equal to 1.")
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero.")
    if format.lower() != "json":
        raise ValueError("only JSON format responses are supported by this helper.")
    if errorformat.lower() != "json":
        raise ValueError("only JSON errorformat responses are supported by this helper.")
    normalized_category = category.strip().lower()
    if normalized_category not in {"road", "parcel"}:
        raise ValueError("category must be either 'ROAD' or 'PARCEL' for address searches.")

    query_params: dict[str, Any] = {
        "service": "search",
        "request": "search",
        "version": "2.0",
        "format": format,
        "errorformat": errorformat,
        "type": "address",
        "category": normalized_category,
        "crs": crs,
        "size": size,
        "page": page,
        "query": address.strip(),
        "key": api_key.strip(),
    }

    if bbox is not None:
        if len(bbox) != 4:
            raise ValueError("bbox must contain exactly four values: minx, miny, maxx, maxy.")
        query_params["bbox"] = ",".join(str(value) for value in bbox)

    if domain:
        query_params["domain"] = domain

    encoded_params = urlencode(_normalize_params(query_params), doseq=True)
    request_url = f"{VWORLD_SEARCH_ENDPOINT}?{encoded_params}"

    try:
        with urlopen(request_url, timeout=timeout) as response:
            raw_body = response.read()
    except HTTPError as exc:
        raise VWorldAPIError(
            f"vworld address search returned HTTP {exc.code}: {exc.reason}"
        ) from exc
    except URLError as exc:
        raise VWorldAPIError(f"Failed to reach vworld address search: {exc.reason}") from exc

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise VWorldAPIError(
            f"Unable to decode JSON response from address search: {exc.msg}"
        ) from exc

    response = payload.get("response")
    if not isinstance(response, Mapping):
        raise VWorldAPIError("Unexpected vworld address search payload: missing 'response'.")
    response_data = dict(response)

    status = response_data.get("status")
    if status == "NOT_FOUND":
        result = response_data.get("result")
        if isinstance(result, Mapping):
            result_dict = dict(result)
            if not isinstance(result_dict.get("items"), list):
                result_dict["items"] = []
        else:
            result_dict = {"items": []}
        response_data["result"] = result_dict
        return response_data
    if status != "OK":
        error_info = response_data.get("error")
        error_message = ""
        if isinstance(error_info, Mapping):
            error_message = str(error_info.get("text") or error_info.get("message") or "")
        elif error_info is not None:
            error_message = str(error_info)
        raise VWorldAPIError(
            f"vworld address search failed (status={status}): {error_message or 'unknown error'}"
        )

    return response_data


__all__ = [
    "call_vworld_api",
    "get_vworld_api_info",
    "VWorldAPIError",
    "search_address",
]
