// Conveniences on top of pages that work without JavaScript. The buttons this script uses are
// in the page from the start, hidden; the script shows them and makes them work. Nothing here
// builds markup from strings, which the Content Security Policy's Trusted Types would refuse.
"use strict";

for (const button of document.querySelectorAll("button.reveal")) {
  const input = button.parentElement.querySelector("input");
  button.hidden = false;
  button.addEventListener("click", () => {
    const shown = input.type === "text";
    input.type = shown ? "password" : "text";
    button.setAttribute("aria-pressed", String(!shown));
  });
}

for (const button of document.querySelectorAll("button[data-copy]")) {
  const label = button.querySelector(".tip");
  button.hidden = false;
  button.addEventListener("click", async () => {
    await navigator.clipboard.writeText(button.dataset.copy);
    button.classList.add("copied");
    label.textContent = button.dataset.copied;
    setTimeout(() => {
      button.classList.remove("copied");
      label.textContent = button.getAttribute("aria-label");
    }, 1500);
  });
}

// Escape hides the hints until the pointer or the focus moves on.
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    document.documentElement.classList.add("hide-tips");
  }
});
for (const type of ["pointerover", "focusin"]) {
  document.addEventListener(type, () => document.documentElement.classList.remove("hide-tips"));
}

// Six digits are a complete code, so there is nothing left to press.
for (const input of document.querySelectorAll("input[data-autosubmit]")) {
  input.addEventListener("input", () => {
    if (/^\d{6}$/.test(input.value.replace(/\s/g, ""))) {
      input.form.requestSubmit();
    }
  });
}

// A form that carries an answer to an application posts itself; the button stays for when
// scripts are off.
for (const form of document.querySelectorAll("form[data-autosubmit-form]")) {
  form.submit();
}

// Passkeys. A form with data-passkey carries the server's options for the browser as JSON, with
// binary values in base64url, and a hidden button. Where the browser supports passkeys, the
// button shows; pressing it asks the browser for a passkey and posts the answer in the form. On
// the sign-in page the browser also offers saved passkeys in the username field.
const fromBase64url = (text) =>
  Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const toBase64url = (buffer) =>
  btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
const withBinaryId = (descriptor) => ({ ...descriptor, id: fromBase64url(descriptor.id) });

// The answer in the shape WebAuthn's toJSON() gives, which not every browser has.
const passkeyAnswer = (credential) => {
  const response = credential.response;
  const fields = { clientDataJSON: toBase64url(response.clientDataJSON) };
  if (response.attestationObject) {
    fields.attestationObject = toBase64url(response.attestationObject);
    fields.transports = response.getTransports?.() ?? [];
  } else {
    fields.authenticatorData = toBase64url(response.authenticatorData);
    fields.signature = toBase64url(response.signature);
    fields.userHandle = response.userHandle && toBase64url(response.userHandle);
  }
  return JSON.stringify({ id: credential.id, type: credential.type, response: fields });
};

for (const form of document.querySelectorAll("form[data-passkey]")) {
  if (!window.PublicKeyCredential) {
    continue;
  }
  const options = JSON.parse(form.dataset.passkey);
  const creating = "user" in options;
  const publicKey = { ...options, challenge: fromBase64url(options.challenge) };
  if (creating) {
    publicKey.user = { ...options.user, id: fromBase64url(options.user.id) };
    publicKey.excludeCredentials = options.excludeCredentials.map(withBinaryId);
  } else {
    publicKey.allowCredentials = options.allowCredentials.map(withBinaryId);
  }
  const post = (credential) => {
    form.elements.credential.value = passkeyAnswer(credential);
    form.submit();
  };

  let autofill = null;
  const offerInUsernameField = async () => {
    if (!(await PublicKeyCredential.isConditionalMediationAvailable?.())) {
      return;
    }
    autofill = new AbortController();
    try {
      post(
        await navigator.credentials.get({
          publicKey,
          mediation: "conditional",
          signal: autofill.signal,
        }),
      );
    } catch {
      // Stopped for the button.
    }
  };
  const signingIn = !creating && options.allowCredentials.length === 0;
  if (signingIn && document.querySelector('input[autocomplete~="webauthn"]')) {
    offerInUsernameField();
  }

  // A button with data-hint asks for a passkey on a phone: the browser shows a QR code for it at
  // once. Phones and tablets have no other phone to scan with, and some browsers say they can't
  // reach one, so there the button stays hidden.
  const onPhone = matchMedia("(pointer: coarse) and (hover: none)").matches;
  for (const button of form.querySelectorAll("button")) {
    const hint = button.dataset.hint;
    if (hint && onPhone) {
      continue;
    }
    button.hidden = false;
    button.addEventListener("click", async () => {
      if (!form.reportValidity()) {
        return;
      }
      autofill?.abort();
      try {
        const ask = creating ? navigator.credentials.create : navigator.credentials.get;
        const credential = await ask.call(navigator.credentials, {
          publicKey: hint ? { ...publicKey, hints: [hint] } : publicKey,
        });
        // A passkey made on a phone shouldn't take this computer's name.
        const name = form.elements.name;
        if (button.dataset.name && name && name.value === name.defaultValue) {
          name.value = button.dataset.name;
        }
        post(credential);
      } catch {
        // Cancelled, or an authenticator that is already added; the browser has said so.
        if (autofill) {
          offerInUsernameField();
        }
      }
    });
  }
  form.querySelector("[data-passkey-unsupported]")?.setAttribute("hidden", "");
  PublicKeyCredential.getClientCapabilities?.()
    .then((capabilities) => {
      if (capabilities.hybridTransport === false) {
        for (const button of form.querySelectorAll("button[data-hint=hybrid]")) {
          button.hidden = true;
        }
      }
    })
    .catch(() => {});

  // Password managers that support these signals forget passkeys removed here and keep the
  // names they show up to date.
  const quietly = (promise) => promise?.catch(() => {});
  if (form.dataset.passkeyUnknown) {
    quietly(
      PublicKeyCredential.signalUnknownCredential?.({
        rpId: options.rpId,
        credentialId: form.dataset.passkeyUnknown,
      }),
    );
  }
  if (creating) {
    const account = { rpId: options.rp.id, userId: options.user.id };
    quietly(
      PublicKeyCredential.signalAllAcceptedCredentials?.({
        ...account,
        allAcceptedCredentialIds: options.excludeCredentials.map((passkey) => passkey.id),
      }),
    );
    quietly(
      PublicKeyCredential.signalCurrentUserDetails?.({
        ...account,
        name: options.user.name,
        displayName: options.user.displayName,
      }),
    );
  }
}
