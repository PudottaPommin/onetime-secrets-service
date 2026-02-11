import "@tailwindplus/elements";
import htmx from "htmx.org";
import "htmx.org/dist/ext/hx-alpine-compat.js";
import Alpine from "alpinejs";
import AlpineCollapse from "@alpinejs/collapse";

window.htmx = htmx;
htmx.config.defaultTimeout = 0;

htmx.on("htmx:config:request", (event) => {
    const meta = document.querySelector('meta[name="csrf-token"]');
    if (meta && event.detail?.ctx?.request?.headers) {
        event.detail.ctx.request.headers["X-CSRF-Token"] = meta.getAttribute("content");
    }
});

Alpine.data("secretForm", () => ({
    maxViews: 1,
    expiration: 3600,
    passphrase: "",
    secret: "",
    showPassphrase: false,
    files: [],
    dragging: false,
    handleDrop(event) {
        this.dragging = false;
        const droppedFiles = event.dataTransfer?.files;
        if (droppedFiles && droppedFiles.length > 0 && this.$refs.fileInput) {
            this.$refs.fileInput.files = droppedFiles;
            this.files = Array.from(droppedFiles).map((f) => f.name);
        }
    },
}));

Alpine.data("authForm", () => ({
    username: "",
    password: "",
    showPassword: false,
}));

Alpine.data("secretPassphrase", () => ({
    passphrase: "",
    showPassphrase: false,
}));

Alpine.data("secretCreated", (url = "") => ({
    url,
    _copied: false,
    _copy() {
        navigator.clipboard.writeText(this.url).then(() => {
            this._copied = true;
            setTimeout(() => {
                this._copied = false;
            }, 2500);
        });
    },
}));

Alpine.data("secretDecrypted", (secret = "") => ({
    secret,
    _copied: false,
    _copy() {
        navigator.clipboard.writeText(this.secret).then(() => {
            this._copied = true;
            setTimeout(() => {
                this._copied = false;
            }, 2500);
        });
    },
}));

window.Alpine = Alpine;
Alpine.plugin(AlpineCollapse);
Alpine.start();

document.addEventListener("htmx:before:sse:message", (event) => {
    if (event.detail.message.event === "sseredirect") {
        window.location.href = event.detail.message.data;
    }
});
