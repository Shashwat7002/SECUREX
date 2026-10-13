"use strict";
const $ = (selector) => document.querySelector(selector);
const state = {
  files: [],
  filter: "all",
  descending: true,
  view: "files",
  initialized: false,
  unlocked: false,
  busy: false,
};
let toastTimer;

function toast(message) {
  $("#toast").textContent = message;
  $("#toast").hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    $("#toast").hidden = true;
  }, 6500);
}
async function api(path, options = {}) {
  const response = await fetch(`/api/${path}`, {
    credentials: "same-origin",
    ...options,
  });
  const type = response.headers.get("content-type") || "";
  const data = type.includes("application/json") ? await response.json() : null;
  if (!response.ok) {
    if (response.status === 423) {
      state.unlocked = false;
      await refreshStatus();
    }
    throw new Error(data?.error || "The operation could not be completed.");
  }
  return data ?? response;
}
const post = (path, body = {}) =>
  api(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
const size = (bytes) => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / 1024 ** 2).toFixed(1)} MiB`;
};
const category = (name) =>
  /\.(png|jpe?g|gif|webp|svg|heic|avif|bmp)$/i.test(name)
    ? "images"
    : /\.(pdf|txt|md|docx?|xlsx?|csv|pptx?|json|rtf|odt)$/i.test(name)
      ? "documents"
      : "other";
const date = (value) =>
  new Date(value).toLocaleDateString(undefined, {
    day: "2-digit",
    month: "short",
    year: "numeric",
  });

async function refreshStatus() {
  const result = await api("status");
  state.initialized = result.initialized;
  state.unlocked = result.unlocked;
  $("#gate").hidden = result.unlocked;
  $("#workspace").hidden = !result.unlocked;
  $("#gate-title").textContent = result.destroyed
    ? "This vault is closed."
    : result.initialized
      ? "Unlock your space."
      : "Make room for privacy.";
  $("#gate-kicker").textContent = result.initialized
    ? "WELCOME HOME"
    : "YOUR KEYS. YOUR CONTROL.";
  $("#gate-copy").textContent = result.destroyed
    ? "The vault key is missing. Restore an encrypted backup to a new directory, or choose a new vault directory."
    : result.initialized
      ? "Enter your passphrase to open your private vault."
      : "Create a passphrase of at least 12 characters to begin.";
  $("#unlock-form").hidden = result.destroyed;
  $("#confirm-wrap").hidden = result.initialized;
  $("#confirm-passphrase").required = !result.initialized;
  $("#passphrase").autocomplete = result.initialized
    ? "current-password"
    : "new-password";
  $("#unlock-button").textContent = result.initialized
    ? "Unlock vault ↗"
    : "Create your vault ↗";
  if (!result.unlocked) {
    state.files = [];
    $("#file-list").replaceChildren();
    $("#event-list").replaceChildren();
    $("#search").value = "";
    $("#verify-result").replaceChildren();
    $("#dialog").close();
    $("#dialog-fields").replaceChildren();
  }
  return result;
}

function renderFiles() {
  const total = state.files.reduce((sum, file) => sum + file.size, 0);
  $("#file-count").textContent = String(state.files.length).padStart(2, "0");
  $("#nav-count").textContent = state.files.length;
  $("#total-size").textContent = size(total);
  const query = $("#search").value.toLocaleLowerCase();
  const visible = state.files
    .filter(
      (file) =>
        (state.filter === "all" || category(file.name) === state.filter) &&
        file.name.toLocaleLowerCase().includes(query),
    )
    .sort((a, b) =>
      state.descending
        ? b.added.localeCompare(a.added)
        : a.added.localeCompare(b.added),
    );
  $("#file-list").replaceChildren();
  for (const file of visible) {
    const row = document.createElement("tr");
    const nameCell = document.createElement("td");
    const wrap = document.createElement("div");
    wrap.className = "filename-cell";
    const icon = document.createElement("span");
    icon.className = "file-icon";
    icon.textContent = file.name.includes(".")
      ? file.name.split(".").pop().slice(0, 4).toUpperCase()
      : "FILE";
    const details = document.createElement("div");
    const name = document.createElement("div");
    name.className = "filename";
    name.textContent = file.name;
    name.title = file.name;
    const kind = document.createElement("div");
    kind.className = "file-type";
    kind.textContent =
      category(file.name) === "images"
        ? "Image"
        : category(file.name) === "documents"
          ? "Document"
          : "File";
    details.append(name, kind);
    wrap.append(icon, details);
    nameCell.append(wrap);
    row.append(nameCell);
    for (const value of [date(file.added), size(file.size)]) {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.append(cell);
    }
    const protection = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = "file-protection";
    badge.textContent = "Encrypted";
    protection.append(badge);
    row.append(protection);
    const actions = document.createElement("td");
    const buttons = document.createElement("div");
    buttons.className = "row-actions";
    const download = document.createElement("button");
    download.textContent = "↓";
    download.setAttribute("aria-label", `Export ${file.name}`);
    download.title = "Export decrypted copy";
    download.onclick = () => exportFile(file);
    const remove = document.createElement("button");
    remove.textContent = "×";
    remove.setAttribute("aria-label", `Remove ${file.name}`);
    remove.title = "Remove file";
    remove.onclick = () => removeFile(file);
    buttons.append(download, remove);
    actions.append(buttons);
    row.append(actions);
    $("#file-list").append(row);
  }
  $("#results-count").textContent =
    `${visible.length} of ${state.files.length} files`;
  $("#empty").hidden = visible.length > 0;
  $("#empty h3").textContent = state.files.length
    ? "Nothing here just yet."
    : "Make yourself at home.";
  $("#empty p").textContent = state.files.length
    ? "Try a different search or category."
    : "Import your first file to start your private collection.";
}
async function loadFiles() {
  state.files = (await api("files")).files;
  renderFiles();
}

async function showView(view) {
  state.view = view;
  for (const name of ["files", "activity", "security"])
    $(`#${name}-view`).hidden = name !== view;
  document
    .querySelectorAll(".nav-item")
    .forEach((button) =>
      button.classList.toggle("active", button.dataset.view === view),
    );
  $("#import-button").hidden = view !== "files";
  $("#breadcrumb").textContent = {
    files: "My vault",
    activity: "Activity",
    security: "Security",
  }[view];
  $("#page-title").textContent = {
    files: "A space of your own.",
    activity: "Nothing behind the scenes.",
    security: "Privacy you can understand.",
  }[view];
  $("#page-description").textContent = {
    files: "Keep what matters close. Keep everything else out.",
    activity: "A quiet record of what happens in your vault.",
    security: "Your protection, your recovery, your decisions.",
  }[view];
  if (view === "activity") {
    const result = await api("events");
    $("#event-list").replaceChildren();
    for (const item of result.events) {
      const row = document.createElement("div");
      row.className = "event";
      const text = document.createElement("span");
      text.textContent = item.message;
      const at = document.createElement("time");
      at.dateTime = item.at;
      at.textContent = new Date(item.at).toLocaleTimeString();
      row.append(text, at);
      $("#event-list").append(row);
    }
  }
}
function dialog({
  title,
  description,
  fields = [],
  submit = "Continue",
  action,
}) {
  $("#dialog-title").textContent = title;
  $("#dialog-description").textContent = description;
  $("#dialog-submit").textContent = submit;
  $("#dialog-error").textContent = "";
  $("#dialog-fields").replaceChildren();
  for (const field of fields) {
    const label = document.createElement("label");
    label.htmlFor = `field-${field.name}`;
    label.textContent = field.label;
    const input = document.createElement("input");
    input.id = label.htmlFor;
    input.name = field.name;
    input.type = field.type || "password";
    input.required = true;
    input.maxLength = 1024;
    input.autocomplete =
      field.name === "replacement" || field.name === "repeat"
        ? "new-password"
        : "current-password";
    $("#dialog-fields").append(label, input);
  }
  $("#dialog-form").onsubmit = async (event) => {
    event.preventDefault();
    $("#dialog-submit").disabled = true;
    try {
      await action(Object.fromEntries(new FormData(event.target)));
      $("#dialog").close();
      $("#dialog-fields").replaceChildren();
    } catch (error) {
      $("#dialog-error").textContent = error.message;
    } finally {
      $("#dialog-submit").disabled = false;
    }
  };
  $("#dialog").showModal();
}
async function downloadResponse(response, name) {
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function exportFile(file) {
  dialog({
    title: "Take a copy with you.",
    description:
      "This exports a decrypted copy to your downloads. Protect it separately from your encrypted vault.",
    submit: "Export file ↓",
    action: async () => {
      await downloadResponse(await api(`files/${file.id}`), file.name);
      toast("Decrypted copy exported.");
    },
  });
}
function removeFile(file) {
  dialog({
    title: "Remove this file?",
    description: `${file.name} will be removed from the live vault. Existing originals, backups, and storage remnants are unaffected.`,
    submit: "Remove file",
    action: async () => {
      await api(`files/${file.id}`, { method: "DELETE" });
      await loadFiles();
      toast("File removed from the vault.");
    },
  });
}
async function importFiles(files) {
  if (state.busy) return;
  state.busy = true;
  $("#import-button").disabled = true;
  const errors = [];
  let imported = 0;
  try {
    for (const file of files) {
      if (file.size > 64 * 1024 * 1024) {
        errors.push(`${file.name}: exceeds 64 MiB`);
        continue;
      }
      const form = new FormData();
      form.append("file", file);
      toast(`Encrypting ${file.name}…`);
      try {
        await api("files", { method: "POST", body: form });
        imported++;
      } catch (error) {
        errors.push(`${file.name}: ${error.message}`);
      }
    }
    if (state.unlocked) await loadFiles();
    toast(
      `${imported} file${imported === 1 ? "" : "s"} encrypted.${errors.length ? ` ${errors.length} failed: ${errors[0]}` : " Originals remain on your device."}`,
    );
  } catch (error) {
    toast(error.message);
  } finally {
    state.busy = false;
    $("#import-button").disabled = false;
    $("#file-input").value = "";
  }
}

$("#unlock-form").onsubmit = async (event) => {
  event.preventDefault();
  $("#gate-error").textContent = "";
  $("#unlock-button").disabled = true;
  try {
    const passphrase = $("#passphrase").value;
    if (!state.initialized && passphrase !== $("#confirm-passphrase").value)
      throw new Error("Passphrases do not match.");
    await post(state.initialized ? "unlock" : "create", { passphrase });
    $("#passphrase").value = "";
    $("#confirm-passphrase").value = "";
    await refreshStatus();
    await loadFiles();
    await showView("files");
  } catch (error) {
    $("#gate-error").textContent = error.message;
  } finally {
    $("#unlock-button").disabled = false;
  }
};
async function lockVault() {
  try {
    await post("lock");
    await refreshStatus();
    $("#passphrase").focus();
  } catch (error) {
    toast(error.message);
  }
}
$("#lock-button").onclick = lockVault;
$(".status-pill").onclick = lockVault;
for (const button of document.querySelectorAll("[data-view]"))
  button.onclick = () =>
    showView(button.dataset.view).catch((error) => toast(error.message));
for (const button of document.querySelectorAll("[data-filter]"))
  button.onclick = () => {
    state.filter = button.dataset.filter;
    document
      .querySelectorAll("[data-filter]")
      .forEach((item) => item.classList.toggle("selected", item === button));
    renderFiles();
  };
$("#search").oninput = renderFiles;
$("#sort-date").onclick = () => {
  state.descending = !state.descending;
  $("#sort-date").textContent = `DATE ADDED ${state.descending ? "↓" : "↑"}`;
  renderFiles();
};
$("#import-button").onclick = $("#browse-button").onclick = () =>
  $("#file-input").click();
$("#file-input").onchange = (event) => importFiles([...event.target.files]);
for (const type of ["dragenter", "dragover"])
  $("#drop-zone").addEventListener(type, (event) => {
    event.preventDefault();
    $("#drop-zone").classList.add("dragging");
  });
for (const type of ["dragleave", "drop"])
  $("#drop-zone").addEventListener(type, (event) => {
    event.preventDefault();
    $("#drop-zone").classList.remove("dragging");
  });
$("#drop-zone").addEventListener("drop", (event) =>
  importFiles([...event.dataTransfer.files]),
);
for (const button of document.querySelectorAll(".dialog-close"))
  button.onclick = () => $("#dialog").close();
$("#dialog").addEventListener("close", () => {
  $("#dialog-fields").replaceChildren();
});
$("#verify-button").onclick = async () => {
  $("#verify-button").disabled = true;
  $("#verify-result").textContent = "Authenticating every file…";
  try {
    const result = await post("verify");
    $("#verify-result").textContent = result.ok
      ? `All ${result.files.length} files passed authentication and checksum checks.${result.orphans ? ` ${result.orphans} orphaned encrypted objects found.` : ""}`
      : `${result.files.filter((file) => !file.ok).length} file(s) failed verification. Restore affected files from a trusted backup.`;
    for (const file of result.files.filter((file) => !file.ok)) {
      const detail = document.createElement("p");
      detail.textContent = `${file.name}: ${file.error}`;
      $("#verify-result").append(detail);
    }
  } catch (error) {
    $("#verify-result").textContent = error.message;
  } finally {
    $("#verify-button").disabled = false;
  }
};
$("#backup-button").onclick = async () => {
  $("#backup-button").disabled = true;
  try {
    await downloadResponse(await api("backup"), "securex-backup.zip");
    toast("Encrypted backup exported. Keep its passphrase safe.");
  } catch (error) {
    toast(error.message);
  } finally {
    $("#backup-button").disabled = false;
  }
};
$("#change-button").onclick = () =>
  dialog({
    title: "Change your passphrase.",
    description:
      "Use at least 12 characters. Backups retain their previous passphrase. Other unlocked processes remain unlocked.",
    fields: [
      { name: "current", label: "Current passphrase" },
      { name: "replacement", label: "New passphrase" },
      { name: "repeat", label: "Confirm new passphrase" },
    ],
    submit: "Update passphrase",
    action: async (values) => {
      if (values.replacement !== values.repeat)
        throw new Error("New passphrases do not match.");
      await post("passphrase", values);
      toast("Passphrase updated.");
    },
  });
$("#destroy-button").onclick = () =>
  dialog({
    title: "Remove your vault key.",
    description:
      "This removes the wrapped key used to unlock this vault. Without another copy of that key, these files cannot be recovered. Backups, snapshots, and storage remnants may retain it.",
    fields: [
      { name: "passphrase", label: "Current passphrase" },
      { name: "confirmation", label: "Type DESTROY to confirm", type: "text" },
    ],
    submit: "Remove vault key",
    action: async (values) => {
      await post("destroy", values);
      await refreshStatus();
      toast("Vault key removed.");
    },
  });

(async () => {
  try {
    const params = new URLSearchParams(location.hash.slice(1));
    const token = params.get("token");
    history.replaceState(null, "", location.pathname);
    if (token) await post("session", { token });
    await refreshStatus();
    if (state.unlocked) {
      await loadFiles();
      await showView("files");
    }
    setInterval(
      () =>
        refreshStatus().catch((error) => {
          $("#gate-error").textContent = error.message;
        }),
      5000,
    );
  } catch (error) {
    $("#gate-error").textContent = error.message;
    $("#unlock-button").disabled = true;
  }
})();
