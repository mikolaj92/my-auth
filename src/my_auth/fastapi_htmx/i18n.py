"""UI copy for passkey login/register pages (server templates + client JS)."""

from __future__ import annotations

from typing import Mapping

# Keep keys stable: templates and passkey-ui.js both read the same map.
_COPY: dict[str, dict[str, str]] = {
    "en": {
        "login_page_title": "Sign in with a passkey",
        "login_eyebrow": "Passkey sign in",
        "login_heading": "Sign in without a password",
        "login_description": (
            "Use your device passkey prompt to continue. "
            "This page keeps WebAuthn API responses as JSON."
        ),
        "login_submit": "Continue with passkey",
        "login_hybrid": "Sign in with a phone (QR code)",
        "login_register": "No account? Register a passkey",
        "login_waiting": "Waiting for the WebAuthn passkey prompt.",
        "register_page_title": "Register a passkey",
        "register_eyebrow": "Passkey registration",
        "register_heading": "Create a passkey",
        "register_description": (
            "Add a passkey to the current account without changing host registration policy."
        ),
        "register_description_bootstrap": "Start by creating a passkey for this account.",
        "register_username_label": "Username",
        "register_username_placeholder": "username",
        "register_username_title": "Username is required and must not contain spaces",
        "register_display_name_label": "Display name (optional)",
        "register_display_name_placeholder": "Your name",
        "register_submit": "Create passkey",
        "register_waiting": "Waiting for registration details.",
        "noscript": (
            "WebAuthn passkeys require JavaScript and a browser with "
            "PublicKeyCredential support."
        ),
        "loading": "Loading…",
        "js_login_success": "Passkey sign-in succeeded.",
        "js_register_success": "Passkey registration succeeded.",
        "js_unsupported": (
            "This browser does not support WebAuthn passkeys with PublicKeyCredential."
        ),
        "js_waiting_prompt": "Waiting for your passkey prompt.",
        "js_hybrid_prompt": (
            "In the passkey prompt, choose another device and scan the QR code."
        ),
        "js_request_failed": "Passkey request failed.",
        "js_username_required": "Username is required.",
        "js_username_spaces": "Username must not contain spaces.",
    },
    "pl": {
        "login_page_title": "Zaloguj się kluczem dostępu",
        "login_eyebrow": "Logowanie kluczem",
        "login_heading": "Zaloguj się bez hasła",
        "login_description": (
            "Użyj monitu klucza dostępu na urządzeniu, aby kontynuować. "
            "Ta strona zwraca odpowiedzi API WebAuthn jako JSON."
        ),
        "login_submit": "Kontynuuj z kluczem dostępu",
        "login_hybrid": "Zaloguj się telefonem (kod QR)",
        "login_register": "Nie masz konta? Zarejestruj klucz dostępu",
        "login_waiting": "Oczekiwanie na monit WebAuthn klucza dostępu.",
        "register_page_title": "Zarejestruj klucz dostępu",
        "register_eyebrow": "Rejestracja klucza",
        "register_heading": "Utwórz klucz dostępu",
        "register_description": (
            "Dodaj klucz dostępu do bieżącego konta bez zmiany polityki rejestracji hosta."
        ),
        "register_description_bootstrap": (
            "Zacznij od utworzenia klucza dostępu dla tego konta."
        ),
        "register_username_label": "Nazwa użytkownika",
        "register_username_placeholder": "nazwa użytkownika",
        "register_username_title": (
            "Nazwa użytkownika jest wymagana i nie może zawierać spacji"
        ),
        "register_display_name_label": "Nazwa wyświetlana (opcjonalnie)",
        "register_display_name_placeholder": "Twoje imię i nazwisko",
        "register_submit": "Utwórz klucz dostępu",
        "register_waiting": "Oczekiwanie na dane rejestracji.",
        "noscript": (
            "Klucze WebAuthn wymagają JavaScriptu oraz przeglądarki "
            "z obsługą PublicKeyCredential."
        ),
        "loading": "Ładowanie…",
        "js_login_success": "Logowanie kluczem dostępu powiodło się.",
        "js_register_success": "Rejestracja klucza dostępu powiodła się.",
        "js_unsupported": (
            "Ta przeglądarka nie obsługuje kluczy WebAuthn (PublicKeyCredential)."
        ),
        "js_waiting_prompt": "Oczekiwanie na monit klucza dostępu.",
        "js_hybrid_prompt": (
            "W monicie klucza wybierz inne urządzenie i zeskanuj kod QR."
        ),
        "js_request_failed": "Żądanie klucza dostępu nie powiodło się.",
        "js_username_required": "Nazwa użytkownika jest wymagana.",
        "js_username_spaces": "Nazwa użytkownika nie może zawierać spacji.",
    },
    "de": {
        "login_page_title": "Mit Passkey anmelden",
        "login_eyebrow": "Passkey-Anmeldung",
        "login_heading": "Ohne Passwort anmelden",
        "login_description": (
            "Nutzen Sie die Passkey-Aufforderung Ihres Geräts, um fortzufahren. "
            "Diese Seite liefert WebAuthn-API-Antworten als JSON."
        ),
        "login_submit": "Mit Passkey fortfahren",
        "login_hybrid": "Mit einem Telefon anmelden (QR-Code)",
        "login_register": "Noch kein Konto? Passkey registrieren",
        "login_waiting": "Warten auf die WebAuthn-Passkey-Aufforderung.",
        "register_page_title": "Passkey registrieren",
        "register_eyebrow": "Passkey-Registrierung",
        "register_heading": "Passkey erstellen",
        "register_description": (
            "Fügen Sie dem aktuellen Konto einen Passkey hinzu, "
            "ohne die Registrierungsrichtlinie des Hosts zu ändern."
        ),
        "register_description_bootstrap": (
            "Erstellen Sie zunächst einen Passkey für dieses Konto."
        ),
        "register_username_label": "Benutzername",
        "register_username_placeholder": "benutzername",
        "register_username_title": (
            "Benutzername ist erforderlich und darf keine Leerzeichen enthalten"
        ),
        "register_display_name_label": "Anzeigename (optional)",
        "register_display_name_placeholder": "Ihr Name",
        "register_submit": "Passkey erstellen",
        "register_waiting": "Warten auf Registrierungsdaten.",
        "noscript": (
            "WebAuthn-Passkeys erfordern JavaScript und einen Browser "
            "mit PublicKeyCredential-Unterstützung."
        ),
        "loading": "Laden…",
        "js_login_success": "Passkey-Anmeldung erfolgreich.",
        "js_register_success": "Passkey-Registrierung erfolgreich.",
        "js_unsupported": (
            "Dieser Browser unterstützt keine WebAuthn-Passkeys (PublicKeyCredential)."
        ),
        "js_waiting_prompt": "Warten auf Ihre Passkey-Aufforderung.",
        "js_hybrid_prompt": (
            "Wählen Sie ein anderes Gerät und scannen Sie den QR-Code."
        ),
        "js_request_failed": "Passkey-Anfrage fehlgeschlagen.",
        "js_username_required": "Benutzername ist erforderlich.",
        "js_username_spaces": "Benutzername darf keine Leerzeichen enthalten.",
    },
}


def ui_copy(locale: str, *, default: str = "en") -> Mapping[str, str]:
    """Return frozen-looking copy for the resolved locale (fallback to default/en)."""
    if locale in _COPY:
        return _COPY[locale]
    if default in _COPY:
        return _COPY[default]
    return _COPY["en"]
