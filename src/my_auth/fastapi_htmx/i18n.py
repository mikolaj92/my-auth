"""UI copy for passkey login/register pages (server templates + client JS)."""

from __future__ import annotations

from collections.abc import Mapping

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
        "login_waiting": "Waiting for the WebAuthn passkey prompt.",
        "register_page_title": "Create an account",
        "register_eyebrow": "Account registration",
        "register_heading": "Create your account",
        "register_description": (
            "Choose a username and create a passkey for your new account."
        ),
        "register_username_label": "Username",
        "register_username_placeholder": "username",
        "register_username_title": "Username is required and must not contain spaces",
        "register_display_name_label": "Display name (optional)",
        "register_display_name_placeholder": "Your name",
        "register_submit": "Create account",
        "register_waiting": "Waiting for registration details.",
        "activation_page_title": "Activate your account",
        "activation_eyebrow": "Account invitation",
        "activation_heading": "Activate your account",
        "activation_description": "Create a passkey for the account in this invitation.",
        "activation_submit": "Activate account",
        "activation_waiting": "Waiting for account activation.",
        "recovery_page_title": "Recover account access",
        "recovery_eyebrow": "Account recovery",
        "recovery_heading": "Recover access",
        "recovery_description": "Create a new passkey for the account bound to this recovery link.",
        "recovery_submit": "Recover access",
        "recovery_waiting": "Waiting for account recovery.",
        "capability_unavailable": "This link is invalid or no longer available. Request a new link.",
        "credentials_page_title": "Your passkeys",
        "credentials_heading": "Your passkeys",
        "credentials_description": "Add, label, and remove passkeys owned by your account.",
        "credentials_add": "Add passkey",
        "credentials_unnamed": "Unnamed passkey",
        "credentials_created": "Created",
        "credentials_label": "Passkey label",
        "credentials_save": "Save label",
        "credentials_remove": "Remove",
        "credentials_empty": "No passkeys are registered.",
        "confirm_credential_removal": "Remove this passkey?",
        "noscript": (
            "WebAuthn passkeys require JavaScript and a browser with "
            "PublicKeyCredential support."
        ),
        "loading": "Loading…",
        "js_login_success": "Passkey sign-in succeeded.",
        "js_register_success": "Passkey registration succeeded.",
        "js_insecure_context": "Passkeys require a secure HTTPS connection.",
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
        "login_waiting": "Oczekiwanie na monit WebAuthn klucza dostępu.",
        "register_page_title": "Utwórz konto",
        "register_eyebrow": "Rejestracja konta",
        "register_heading": "Utwórz swoje konto",
        "register_description": (
            "Wybierz nazwę użytkownika i utwórz klucz dostępu do nowego konta."
        ),
        "register_username_label": "Nazwa użytkownika",
        "register_username_placeholder": "nazwa użytkownika",
        "register_username_title": (
            "Nazwa użytkownika jest wymagana i nie może zawierać spacji"
        ),
        "register_display_name_label": "Nazwa wyświetlana (opcjonalnie)",
        "register_display_name_placeholder": "Twoje imię i nazwisko",
        "register_submit": "Utwórz konto",
        "register_waiting": "Oczekiwanie na dane rejestracji.",
        "activation_page_title": "Aktywuj konto",
        "activation_eyebrow": "Zaproszenie do konta",
        "activation_heading": "Aktywuj konto",
        "activation_description": "Utwórz klucz dostępu dla konta wskazanego w zaproszeniu.",
        "activation_submit": "Aktywuj konto",
        "activation_waiting": "Oczekiwanie na aktywację konta.",
        "recovery_page_title": "Odzyskaj dostęp do konta",
        "recovery_eyebrow": "Odzyskiwanie konta",
        "recovery_heading": "Odzyskaj dostęp",
        "recovery_description": "Utwórz nowy klucz dostępu dla konta przypisanego do tego odnośnika odzyskiwania.",
        "recovery_submit": "Odzyskaj dostęp",
        "recovery_waiting": "Oczekiwanie na odzyskanie dostępu.",
        "capability_unavailable": "Ten odnośnik jest nieprawidłowy lub nie jest już dostępny. Poproś o nowy odnośnik.",
        "credentials_page_title": "Twoje klucze dostępu",
        "credentials_heading": "Twoje klucze dostępu",
        "credentials_description": "Dodawaj, nazywaj i usuwaj klucze należące do Twojego konta.",
        "credentials_add": "Dodaj klucz dostępu",
        "credentials_unnamed": "Klucz bez nazwy",
        "credentials_created": "Utworzono",
        "credentials_label": "Nazwa klucza",
        "credentials_save": "Zapisz nazwę",
        "credentials_remove": "Usuń",
        "credentials_empty": "Nie zarejestrowano kluczy dostępu.",
        "confirm_credential_removal": "Usunąć ten klucz dostępu?",
        "noscript": (
            "Klucze WebAuthn wymagają JavaScriptu oraz przeglądarki "
            "z obsługą PublicKeyCredential."
        ),
        "loading": "Ładowanie…",
        "js_login_success": "Logowanie kluczem dostępu powiodło się.",
        "js_register_success": "Rejestracja klucza dostępu powiodła się.",
        "js_insecure_context": (
            "Klucze dostępu wymagają bezpiecznego połączenia HTTPS."
        ),
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
        "login_waiting": "Warten auf die WebAuthn-Passkey-Aufforderung.",
        "register_page_title": "Passkey registrieren",
        "register_eyebrow": "Passkey-Registrierung",
        "register_heading": "Passkey erstellen",
        "register_description": (
            "Fügen Sie dem aktuellen Konto einen Passkey hinzu, "
            "ohne die Registrierungsrichtlinie des Hosts zu ändern."
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
        "activation_page_title": "Konto aktivieren",
        "activation_eyebrow": "Kontoeinladung",
        "activation_heading": "Konto aktivieren",
        "activation_description": "Erstellen Sie einen Passkey für das in dieser Einladung angegebene Konto.",
        "activation_submit": "Konto aktivieren",
        "activation_waiting": "Warten auf die Kontoaktivierung.",
        "recovery_page_title": "Kontozugriff wiederherstellen",
        "recovery_eyebrow": "Kontowiederherstellung",
        "recovery_heading": "Zugriff wiederherstellen",
        "recovery_description": "Erstellen Sie einen neuen Passkey für das mit diesem Wiederherstellungslink verknüpfte Konto.",
        "recovery_submit": "Zugriff wiederherstellen",
        "recovery_waiting": "Warten auf die Kontowiederherstellung.",
        "capability_unavailable": "Dieser Link ist ungültig oder nicht mehr verfügbar. Fordern Sie einen neuen Link an.",
        "credentials_page_title": "Ihre Passkeys",
        "credentials_heading": "Ihre Passkeys",
        "credentials_description": "Fügen Sie Passkeys Ihres Kontos hinzu, benennen oder entfernen Sie sie.",
        "credentials_add": "Passkey hinzufügen",
        "credentials_unnamed": "Unbenannter Passkey",
        "credentials_created": "Erstellt",
        "credentials_label": "Passkey-Bezeichnung",
        "credentials_save": "Bezeichnung speichern",
        "credentials_remove": "Entfernen",
        "credentials_empty": "Keine Passkeys registriert.",
        "confirm_credential_removal": "Diesen Passkey entfernen?",
        "noscript": (
            "WebAuthn-Passkeys erfordern JavaScript und einen Browser "
            "mit PublicKeyCredential-Unterstützung."
        ),
        "loading": "Laden…",
        "js_login_success": "Passkey-Anmeldung erfolgreich.",
        "js_register_success": "Passkey-Registrierung erfolgreich.",
        "js_insecure_context": ("Passkeys erfordern eine sichere HTTPS-Verbindung."),
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
