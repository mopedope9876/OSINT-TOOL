"""
osint/plugins/phone_info.py
----------------------------
Offline phone number analysis using the `phonenumbers` library.

No network request, no API key, completely free.
Parses any international phone number and returns:
  - country, region, carrier
  - number type (mobile, fixed-line, toll-free, VOIP, etc.)
  - validity check
  - formatted versions (international, national, E.164)
"""

from __future__ import annotations

try:
    import phonenumbers
    import phonenumbers.carrier as pncarrier
    import phonenumbers.geocoder as pngeo
    import phonenumbers.timezone as pntz
    _HAS_PHONENUMBERS = True
except ImportError:
    _HAS_PHONENUMBERS = False

from osint.logger import get_logger
from osint.models import AppConfig, PluginResult
from osint.plugin_base import BasePlugin

logger = get_logger(__name__)

_TYPE_NAMES = {
    0:  "FIXED_LINE",
    1:  "MOBILE",
    2:  "FIXED_LINE_OR_MOBILE",
    3:  "TOLL_FREE",
    4:  "PREMIUM_RATE",
    5:  "SHARED_COST",
    6:  "VOIP",
    7:  "PERSONAL_NUMBER",
    8:  "PAGER",
    9:  "UAN",
    10: "VOICEMAIL",
    99: "UNKNOWN",
}


class PhoneInfoPlugin(BasePlugin):
    name = "Phone Number Analysis"
    description = "Offline: validates number, detects country, carrier, and type. No key needed."
    supported_identifiers = ["phone"]

    def run(self, identifier_type: str, identifier_value: str, config: AppConfig) -> PluginResult:
        if not _HAS_PHONENUMBERS:
            return PluginResult(
                plugin_name=self.name, identifier_type=identifier_type,
                identifier_value=identifier_value, success=False,
                error="phonenumbers library not installed. Run: pip install phonenumbers",
            )

        try:
            parsed = phonenumbers.parse(identifier_value, None)
        except phonenumbers.phonenumberutil.NumberParseException as exc:
            return PluginResult(
                plugin_name=self.name, identifier_type=identifier_type,
                identifier_value=identifier_value, success=False,
                error=f"Could not parse number: {exc}. Make sure to include the country code (e.g. +1 for US).",
            )

        is_valid   = phonenumbers.is_valid_number(parsed)
        is_poss    = phonenumbers.is_possible_number(parsed)
        num_type   = phonenumbers.number_type(parsed)
        region     = phonenumbers.region_code_for_number(parsed)
        geo        = pngeo.description_for_number(parsed, "en")
        carrier    = pncarrier.name_for_number(parsed, "en")
        timezones  = list(pntz.time_zones_for_number(parsed))

        fmt_intl   = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        fmt_natl   = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
        fmt_e164   = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)

        data = {
            "is_valid":           is_valid,
            "is_possible":        is_poss,
            "international_format": fmt_intl,
            "national_format":    fmt_natl,
            "e164_format":        fmt_e164,
            "country_code":       f"+{parsed.country_code}",
            "country_region":     region,
            "geographic_area":    geo or None,
            "carrier":            carrier or None,
            "number_type":        _TYPE_NAMES.get(num_type, "UNKNOWN"),
            "timezones":          timezones,
        }
        data = {k: v for k, v in data.items() if v not in (None, [], "")}

        return PluginResult(
            plugin_name=self.name, identifier_type=identifier_type,
            identifier_value=identifier_value, success=True,
            data=data, source_url=None,
        )

    def get_summary(self, result: PluginResult) -> str:
        if not result.success:
            return result.error or "Unknown error"
        d = result.data
        valid = "Valid" if d.get("is_valid") else "INVALID"
        ntype = d.get("number_type", "")
        region = d.get("country_region", "")
        carrier = d.get("carrier", "")
        geo = d.get("geographic_area", "")
        parts = [valid]
        if ntype and ntype != "UNKNOWN":
            parts.append(ntype)
        if geo:
            parts.append(geo)
        elif region:
            parts.append(region)
        if carrier:
            parts.append(carrier)
        return " · ".join(parts)
