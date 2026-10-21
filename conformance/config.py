"""Writes unlatch.json, the configuration for testing a local Unlatch with the OpenID conformance
suite. Usage: python config.py <client id> <secret> <second client id> <second secret>

README.md in this directory says how to set up Unlatch and run the plans.
"""
import json
import sys

OP = "https://host.docker.internal:9443"
USER, PASSWORD = "tester", "conformance suite password"
# The suite builds its redirect URIs from this.
ALIAS = "unlatch"


def task(name, match, commands, optional=False):
    return {"task": name, "match": match, "optional": optional, "commands": commands}


# Waits for a page and gives the suite a screenshot of it, to be reviewed by hand.
SCREENSHOT = ["wait", "xpath", "//*", 10, ".", "update-image-placeholder"]


def authorization(screenshot_login=False):
    """Signs in, consents, and posts a form_post answer, whichever of these the flow asks for.
    The suite's browser runs no scripts, so it clicks what a script would."""
    login = [
        ["text", "name", "username", USER, "optional"],
        ["text", "name", "password", PASSWORD, "optional"],
        ["click", "css", "form[action='/login'] button.primary"],
    ]
    if screenshot_login:
        login.insert(0, ["wait", "xpath", "//*", 10, "Sign in", "update-image-placeholder-optional"])
    post = ["click", "css", "form[data-autosubmit-form] button", "optional"]
    return {
        "match": OP + "/authorize*",
        "tasks": [
            task("Post an error", OP + "/authorize?*", [post], optional=True),
            task("Login", OP + "/login*", login, optional=True),
            task("Consent", OP + "/authorize/continue*",
                 [["click", "css", "button[value=allow]", "optional"], post], optional=True),
            task("Verify Complete", "*/test/*/callback*", [["wait", "id", "submission_complete", 10]]),
        ],
    }


def logout(back=True):
    """Confirms signing out, unless a valid id_token_hint made that unnecessary. Then waits to be
    sent back to the client, or, with `back` false, screenshots the page Unlatch shows instead."""
    confirm = [["click", "css", "form[action='/end-session'] button.primary", "optional"]]
    end = task("Verify Complete", "*/test/*/post*", [])
    if not back:
        end = task("Expect the signed-out page", OP + "/end-session*", [SCREENSHOT])
    return {
        "match": OP + "/end-session*",
        "tasks": [task("Choose logout option", OP + "/end-session*", confirm, optional=True), end],
    }


def logout_refused():
    """A logout request Unlatch must not send back to the client."""
    return {"match": OP + "/end-session*", "tasks": [task("Expect an error page", OP + "/end-session*", [SCREENSHOT])]}


def error_page():
    """An authorization request Unlatch must refuse with a page rather than a redirect."""
    return [{"match": OP + "/authorize*", "tasks": [task("Expect an error page", OP + "/authorize*", [SCREENSHOT])]}]


ERROR_PAGE_TESTS = [
    "oidcc-ensure-registered-redirect-uri",
    "oidcc-ensure-redirect-uri-in-authorization-request",
    "oidcc-ensure-request-object-with-redirect-uri",
    "oidcc-redirect-uri-query-added",
    "oidcc-redirect-uri-query-mismatch",
]
LOGOUT_ERROR_TESTS = [
    "oidcc-rp-initiated-logout-bad-id-token-hint",
    "oidcc-rp-initiated-logout-bad-post-logout-redirect-uri",
    "oidcc-rp-initiated-logout-modified-id-token-hint",
    "oidcc-rp-initiated-logout-no-id-token-hint",
    "oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri",
]
LOGOUT_WITHOUT_RETURN_TESTS = [
    "oidcc-rp-initiated-logout-no-params",
    "oidcc-rp-initiated-logout-no-post-logout-redirect-uri",
    "oidcc-rp-initiated-logout-only-state",
]

client_id, secret, client2_id, secret2 = sys.argv[1:5]
client = {"client_id": client_id, "client_secret": secret}
override = {name: {"browser": error_page()} for name in ERROR_PAGE_TESTS}
override |= {name: {"browser": [authorization(), logout_refused()]} for name in LOGOUT_ERROR_TESTS}
override |= {name: {"browser": [authorization(), logout(back=False)]} for name in LOGOUT_WITHOUT_RETURN_TESTS}
for name in ["oidcc-prompt-login", "oidcc-max-age-1"]:
    override[name] = {"browser": [authorization(screenshot_login=True), logout()]}
config = {
    "alias": ALIAS,
    "description": "Unlatch",
    "server": {"discoveryUrl": OP + "/.well-known/openid-configuration"},
    "client": client,
    # The client_secret_post test takes its client from here; one client may accept both methods.
    "client_secret_post": client,
    "client2": {"client_id": client2_id, "client_secret": secret2},
    "browser": [authorization(), logout()],
    "override": override,
}
with open("unlatch.json", "w", encoding="utf-8") as file:
    json.dump(config, file, indent=2)
