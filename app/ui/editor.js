// Credential editor and value reveal. Loaded after app.js, whose helpers
// (h, t, call, state, render) it uses.
"use strict";

// ---------- Editor ----------

// The date input's value for a stored expiry, in local time like the
// 23:59:59 the editor stores, so reopening and saving keeps the same day.
function localDate(seconds) {
  const date = new Date(seconds * 1000);
  const pad = (number) => String(number).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

function componentRow(component, editing) {
  const row = h("div", { class: "component-row" },
    h("input", { class: "component-name", value: component?.name ?? "", placeholder: t("editor.componentName"), "aria-label": t("editor.componentName"), required: true }),
    h("input", { class: "component-variable mono", value: component?.environmentVariable ?? "", placeholder: t("editor.variableNone"), "aria-label": t("editor.variable"), pattern: "[A-Za-z_][A-Za-z0-9_]*" }),
    h("input", { class: "component-value", type: "password", autocomplete: "off", placeholder: editing && component ? t("editor.valueUnchanged") : t("editor.value"), "aria-label": t("editor.value"), required: !(editing && component) }),
    h("button", { type: "button", class: "ghost small", onclick: () => row.remove() }, t("editor.remove")),
  );
  return row;
}

function openEditor(credential) {
  const dialog = document.getElementById("editor");
  const editing = Boolean(credential);
  const components = h("div", { class: "components" },
    (credential?.components ?? [{ name: "token", environmentVariable: "" }]).map((component) =>
      componentRow(editing ? component : { ...component, isNew: true }, editing),
    ),
  );
  const name = h("input", { value: credential?.name ?? "", required: true, maxlength: 128 });
  const group = h("input", { value: credential?.group ?? "", placeholder: t("editor.groupPlaceholder") });
  const usage = h("textarea", { rows: 3, placeholder: t("editor.usagePlaceholder"), maxlength: 4096 }, credential?.usageInstructions ?? "");
  const permission = h("select", { disabled: editing },
    ["ask", "allow", "hidden"].map((value) => h("option", { value, selected: (credential?.permission ?? "ask") === value }, `${t(`permission.${value}`)} — ${t(`permission.${value}Hint`)}`)),
  );
  const expiry = h("input", {
    type: "date",
    value: credential?.expiresAt ? localDate(credential.expiresAt) : "",
  });
  const form = h("form", {
    method: "dialog",
    class: "editor",
    onsubmit: async (event) => {
      event.preventDefault();
      const items = [...components.querySelectorAll(".component-row")].map((row) => {
        const value = row.querySelector(".component-value").value;
        const variable = row.querySelector(".component-variable").value.trim();
        return {
          name: row.querySelector(".component-name").value.trim(),
          environmentVariable: variable || null,
          value: value === "" && editing ? null : value,
        };
      });
      const expiresAt = expiry.value ? Math.floor(new Date(`${expiry.value}T23:59:59`).getTime() / 1000) : null;
      const input = {
        name: name.value,
        usageInstructions: usage.value,
        group: group.value || null,
        components: items,
        expiresAt,
      };
      try {
        if (editing) await call("update_credential", { id: credential.id, input });
        else await call("create_credential", { input: { ...input, permission: permission.value } });
      } catch (_) {
        return;
      }
      for (const field of components.querySelectorAll(".component-value")) field.value = "";
      dialog.close();
      toast(t("toast.saved"));
      state.credentials = await invoke("list_credentials");
      render();
    },
  },
    h("h2", {}, editing ? t("editor.editTitle") : t("editor.newTitle")),
    h("label", {}, t("editor.name"), name),
    h("div", { class: "two" },
      h("label", {}, t("editor.group"), group),
      h("label", {}, t("editor.permission"), permission),
    ),
    h("label", {}, t("editor.usage"), usage),
    h("fieldset", {},
      h("legend", {}, t("editor.components")),
      h("div", { class: "component-head muted small" },
        h("span", {}, t("editor.componentName")), h("span", {}, t("editor.variable")), h("span", {}, t("editor.value")), h("span"),
      ),
      components,
      h("button", { type: "button", class: "ghost small", onclick: () => components.append(componentRow(null, false)) }, `+ ${t("editor.addComponent")}`),
    ),
    h("label", { class: "narrow" }, t("editor.expires"), expiry),
    h("footer", { class: "actions" },
      h("button", {
        type: "button",
        class: "secondary",
        onclick: () => {
          for (const field of components.querySelectorAll(".component-value")) field.value = "";
          dialog.close();
        },
      }, t("editor.cancel")),
      h("button", { type: "submit", class: "primary" }, t("editor.save")),
    ),
  );
  dialog.replaceChildren(form);
  dialog.showModal();
  name.focus();
}

async function reveal(credential) {
  let values;
  try {
    values = await call("reveal_values", { id: credential.id });
  } catch (_) {
    return;
  }
  const dialog = document.getElementById("reveal");
  const close = () => {
    dialog.replaceChildren();
    dialog.close();
  };
  dialog.replaceChildren(
    h("div", { class: "editor" },
      h("h2", {}, credential.name),
      h("dl", { class: "pairs" },
        credential.components.map((component, index) => [
          h("dt", {}, component.name),
          h("dd", { class: "code-row" }, h("code", { class: "mono secret" }, values[index]), copyButton(values[index])),
        ]),
      ),
      h("footer", { class: "actions" }, h("button", { type: "button", class: "primary", onclick: close }, t("reveal.close"))),
    ),
  );
  values = null;
  dialog.showModal();
  // Values do not stay on screen.
  setTimeout(() => dialog.open && close(), 30000);
}

async function removeCredential(credential) {
  if (!window.confirm(`${credential.name}\n\n${t("confirm.delete")}`)) return;
  try {
    await call("delete_credential", { id: credential.id });
  } catch (_) {
    return;
  }
  toast(t("toast.deleted"));
  state.credentials = await invoke("list_credentials");
  render();
}
