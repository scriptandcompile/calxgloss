/* ==========================================================================
   Shared UI primitives — toasts and modals
   ========================================================================== */

export function showToast(message, type = "info", duration = 4000) {
    const container = document.getElementById("toast-container");
    if (!container) return;

    const el = document.createElement("div");
    el.className = `toast ${type}`;
    el.textContent = message;
    container.appendChild(el);

    setTimeout(() => {
        el.classList.add("toast-out");
        setTimeout(() => el.remove(), 250);
    }, duration);
}

export function showModal(title, submitLabel, onSubmit) {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";

    const modal = document.createElement("div");
    modal.className = "modal";
    modal.innerHTML = `
        <h3>${title}</h3>
        <textarea id="modal-input" placeholder="Enter details..."></textarea>
        <div class="modal-actions">
            <button class="btn btn-secondary" id="modal-cancel">Cancel</button>
            <button class="btn btn-primary" id="modal-confirm">${submitLabel}</button>
        </div>
    `;

    overlay.appendChild(modal);
    document.body.appendChild(overlay);

    const input = modal.querySelector("#modal-input");
    input.focus();

    const close = () => overlay.remove();

    modal.querySelector("#modal-cancel").addEventListener("click", close);
    overlay.addEventListener("click", (e) => { if (e.target === overlay) close(); });

    modal.querySelector("#modal-confirm").addEventListener("click", () => {
        const value = input.value.trim();
        close();
        onSubmit(value);
    });

    input.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && !e.shiftKey) {
            e.preventDefault();
            modal.querySelector("#modal-confirm").click();
        }
        if (e.key === "Escape") close();
    });
}
