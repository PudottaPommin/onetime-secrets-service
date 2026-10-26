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

function formatBytes(bytes) {
    if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
    const units = ["B", "KB", "MB", "GB"];
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    const value = bytes / Math.pow(1024, i);
    return `${i === 0 ? value : value.toFixed(1)} ${units[i]}`;
}

Alpine.data("secretForm", () => ({
    maxViews: 1,
    expiration: 3600,
    passphrase: "",
    secret: "",
    showPassphrase: false,
    files: [],
    dragging: false,
    uploading: false,
    processing: false,
    uploadProgress: 0,
    uploadLoaded: "0 B",
    uploadTotal: "",

    init() {
        this.$el.addEventListener("htmx:before:request", (e) => this.beforeRequest(e));
        this.$el.addEventListener("htmx:finally:request", () => this.finallyRequest());
    },

    updateFiles(fileList) {
        this.files = Array.from(fileList || []).map((f) => ({
            name: f.name,
            size: f.size,
            formattedSize: formatBytes(f.size),
        }));
    },

    handleDrop(event) {
        this.dragging = false;
        const droppedFiles = event.dataTransfer?.files;
        if (droppedFiles && droppedFiles.length > 0 && this.$refs.fileInput) {
            this.$refs.fileInput.files = droppedFiles;
            this.updateFiles(droppedFiles);
        }
    },

    beforeRequest(event) {
        const ctx = event.detail?.ctx;
        if (!ctx) return;

        this.uploading = true;
        this.processing = false;
        this.uploadProgress = 0;
        this.uploadLoaded = "0 B";
        const totalFileBytes = this.files.reduce((sum, f) => sum + (f.size || 0), 0);
        this.uploadTotal = totalFileBytes > 0 ? formatBytes(totalFileBytes) : "";

        ctx.fetch = (url, init) =>
            new Promise((resolve, reject) => {
                const xhr = new XMLHttpRequest();
                xhr.open(init.method || "PUT", url, true);

                if (init.credentials === "include") {
                    xhr.withCredentials = true;
                }

                if (init.headers) {
                    for (const [k, v] of Object.entries(init.headers)) {
                        xhr.setRequestHeader(k, v);
                    }
                }

                if (init.signal) {
                    if (init.signal.aborted) {
                        reject(new DOMException("Aborted", "AbortError"));
                        return;
                    }
                    init.signal.addEventListener("abort", () => xhr.abort(), { once: true });
                }

                xhr.upload.addEventListener("progress", (e) => {
                    if (e.lengthComputable && e.total > 0) {
                        this.uploadProgress = Math.min(100, Math.round((e.loaded / e.total) * 100));
                        this.uploadLoaded = formatBytes(e.loaded);
                        this.uploadTotal = formatBytes(e.total);
                        if (e.loaded >= e.total) {
                            this.processing = true;
                        }
                    }
                });

                xhr.upload.addEventListener("load", () => {
                    this.uploadProgress = 100;
                    this.processing = true;
                });

                xhr.addEventListener("load", () => {
                    const headers = new Headers();
                    for (const line of xhr.getAllResponseHeaders().trim().split(/[\r\n]+/)) {
                        const idx = line.indexOf(":");
                        if (idx > 0) {
                            headers.append(line.slice(0, idx).trim(), line.slice(idx + 1).trim());
                        }
                    }
                    const body = [204, 205, 304].includes(xhr.status) ? null : xhr.responseText;
                    resolve(
                        new Response(body, {
                            status: xhr.status,
                            statusText: xhr.statusText,
                            headers,
                        }),
                    );
                });

                xhr.addEventListener("error", () => reject(new TypeError("Network request failed")));
                xhr.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));

                xhr.send(init.body);
            });
    },

    finallyRequest() {
        this.uploading = false;
        this.processing = false;
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
