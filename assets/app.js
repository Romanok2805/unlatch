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
