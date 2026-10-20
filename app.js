"use strict";

/*
 * Private Gallery - Argon2id
 * Password KDF: Argon2id
 * Encryption: AES-256-GCM
 *
 * Important:
 * Client-side lock counters can be bypassed by
 * someone who can modify the browser/app.
 */

const $ = (id) => document.getElementById(id);

const META_KEY = "private_gallery_argon2id_meta_v1";
const DB_NAME = "private_gallery_argon2id_db_v1";
const STORE_NAME = "media";

const MIN_PASSWORD_LENGTH = 12;

// Argon2 memory is measured in KiB.
// Test performance on your phone before increasing this.
const ARGON_MEMORY = 32768;
const ARGON_TIME = 3;
const ARGON_PARALLELISM = 1;
const ARGON_HASH_LENGTH = 32;

const LOCK_MS = 60_000;
const MAX_FAILURES = 10;
const LOCK_EVERY = 3;
const IDLE_MS = 60_000;

let vaultKey = null;
let firstPassword = null;
let busy = false;
let idleTimer = null;
let countdownTimer = null;
let currentObjectURLs = [];


/* =========================
   BASIC HELPERS
========================= */

function setStatus(message) {
    const box = $("statusBox");

    if (box) {
        box.textContent = message;
        box.style.display = message ? "block" : "none";
    }
}

function showScreen(screenId) {
    const screenIds = [
        "setupScreen",
        "unlockScreen",
        "recoveryScreen",
        "recoveryDisplayScreen",
        "galleryScreen"
    ];

    for (const id of screenIds) {
        const element = $(id);

        if (element) {
            element.hidden = id !== screenId;
            element.style.display =
                id === screenId ? "" : "none";
        }
    }

    setStatus("");

    window.scrollTo({
        top: 0,
        behavior: "instant"
    });
}

function showUnlockStep(stepNumber) {
    showScreen("unlockScreen");

    if ($("step1")) {
        $("step1").hidden = stepNumber !== 1;
        $("step1").style.display =
            stepNumber === 1 ? "" : "none";
    }

    if ($("step2")) {
        $("step2").hidden = stepNumber !== 2;
        $("step2").style.display =
            stepNumber === 2 ? "" : "none";
    }

    setStatus("");
}

function readMeta() {
    try {
        const value = localStorage.getItem(META_KEY);
        return value ? JSON.parse(value) : null;
    } catch {
        return null;
    }
}

function saveMeta(meta) {
    localStorage.setItem(
        META_KEY,
        JSON.stringify(meta)
    );
}

function randomBytes(length) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
}

function toBase64(bytes) {
    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary);
}

function fromBase64(value) {
    const binary = atob(value);

    return Uint8Array.from(
        binary,
        character => character.charCodeAt(0)
    );
}

function makeRecoveryCode() {
    const bytes = randomBytes(32);

    return Array.from(
        bytes,
        byte => byte.toString(16).padStart(2, "0")
    ).join("").toUpperCase();
}

function secureEnvironmentAvailable() {
    return Boolean(
        window.crypto &&
        crypto.subtle &&
        window.indexedDB &&
        window.isSecureContext
    );
}


/* =========================
   ARGON2ID
========================= */

async function deriveArgonKey(password, salt) {
    if (
        typeof window.argon2 === "undefined" ||
        typeof window.argon2.hash !== "function"
    ) {
        throw new Error(
            "Argon2 library is not loaded."
        );
    }

    const result = await window.argon2.hash({
        pass: password,
        salt,
        time: ARGON_TIME,
        mem: ARGON_MEMORY,
        hashLen: ARGON_HASH_LENGTH,
        parallelism: ARGON_PARALLELISM,
        type: window.argon2.ArgonType.Argon2id
    });

    return new Uint8Array(result.hash);
}


/* =========================
   AES-256-GCM
========================= */

async function importAESKey(rawBytes) {
    return crypto.subtle.importKey(
        "raw",
        rawBytes,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
    );
}

async function encryptBytes(key, bytes) {
    const iv = randomBytes(12);

    const encrypted = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv
        },
        key,
        bytes
    );

    return {
        iv: toBase64(iv),
        data: toBase64(new Uint8Array(encrypted))
    };
}

async function decryptBytes(key, record) {
    const iv = fromBase64(record.iv);
    const encrypted = fromBase64(record.data);

    const decrypted = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv
        },
        key,
        encrypted
    );

    return new Uint8Array(decrypted);
}


/* =========================
   PASSWORD-BASED KEY WRAP
========================= */

async function wrapVaultKey(password1, password2, salt, rawVaultKey) {
    // Both passwords are required to derive the wrapping key.
    const combinedPassword =
        password1 + "\u0000" + password2;

    const derivedBytes = await deriveArgonKey(
        combinedPassword,
        salt
    );

    const wrappingKey = await importAESKey(
        derivedBytes
    );

    return encryptBytes(
        wrappingKey,
        rawVaultKey
    );
}

async function unwrapVaultKey(password1, password2, meta) {
    const combinedPassword =
        password1 + "\u0000" + password2;

    const derivedBytes = await deriveArgonKey(
        combinedPassword,
        fromBase64(meta.passwordSalt)
    );

    const wrappingKey = await importAESKey(
        derivedBytes
    );

    const rawKey = await decryptBytes(
        wrappingKey,
        meta.wrappedVaultKey
    );

    return importAESKey(rawKey);
}


/* =========================
   RECOVERY KEY
========================= */

async function deriveRecoveryKey(code, salt) {
    // The recovery code contains 256 random bits.
    // Argon2id is also used here to derive the recovery key.
    const raw = await deriveArgonKey(
        code,
        salt
    );

    return importAESKey(raw);
}


/* =========================
   INDEXEDDB
========================= */

function openDatabase() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, 1);

        request.onupgradeneeded = () => {
            const db = request.result;

            if (!db.objectStoreNames.contains(STORE_NAME)) {
                db.createObjectStore(
                    STORE_NAME,
                    { keyPath: "id" }
                );
            }
        };

        request.onsuccess = () => {
            resolve(request.result);
        };

        request.onerror = () => {
            reject(request.error);
        };
    });
}

async function dbPut(record) {
    const db = await openDatabase();

    return new Promise((resolve, reject) => {
        const transaction = db.transaction(
            STORE_NAME,
            "readwrite"
        );

        transaction.objectStore(STORE_NAME).put(record);

        transaction.oncomplete = () => {
            db.close();
            resolve();
        };

        transaction.onerror = () => {
            db.close();
            reject(transaction.error);
        };
    });
}

async function dbGetAll() {
    const db = await openDatabase();

    return new Promise((resolve, reject) => {
        const transaction = db.transaction(
            STORE_NAME,
            "readonly"
        );

        const request = transaction
            .objectStore(STORE_NAME)
            .getAll();

        request.onsuccess = () => {
            db.close();
            resolve(request.result || []);
        };

        request.onerror = () => {
            db.close();
            reject(request.error);
        };
    });
}

async function dbDelete(id) {
    const db = await openDatabase();

    return new Promise((resolve, reject) => {
        const transaction = db.transaction(
            STORE_NAME,
            "readwrite"
        );

        transaction.objectStore(STORE_NAME).delete(id);

        transaction.oncomplete = () => {
            db.close();
            resolve();
        };

        transaction.onerror = () => {
            db.close();
            reject(transaction.error);
        };
    });
}


/* =========================
   FAILURE COUNTERS
========================= */

function ensureFailureState(meta) {
    if (!Number.isInteger(meta.failures)) {
        meta.failures = 0;
    }

    if (!Number.isFinite(meta.lockUntil)) {
        meta.lockUntil = 0;
    }

    if (typeof meta.recoveryRequired !== "boolean") {
        meta.recoveryRequired = false;
    }
}

function remainingLockSeconds(meta) {
    return Math.max(
        0,
        Math.ceil(
            (meta.lockUntil - Date.now()) / 1000
        )
    );
}

function registerFailure() {
    const meta = readMeta();

    if (!meta) {
        return;
    }

    ensureFailureState(meta);

    meta.failures += 1;

    if (meta.failures >= MAX_FAILURES) {
        meta.recoveryRequired = true;
        meta.lockUntil = 0;
        saveMeta(meta);

        firstPassword = null;

        showScreen("recoveryScreen");

        setStatus(
            "Too many failed attempts. Enter your recovery code."
        );

        return;
    }

    if (meta.failures % LOCK_EVERY === 0) {
        meta.lockUntil = Date.now() + LOCK_MS;
    }

    saveMeta(meta);

    firstPassword = null;

    if (remainingLockSeconds(meta) > 0) {
        showUnlockStep(1);

        setStatus(
            "Locked. Try again in " +
            remainingLockSeconds(meta) +
            " seconds."
        );
    } else {
        showUnlockStep(1);

        setStatus(
            "Incorrect password combination. Try again."
        );
    }

    startCountdown();
}

function resetFailures() {
    const meta = readMeta();

    if (!meta) {
        return;
    }

    meta.failures = 0;
    meta.lockUntil = 0;
    meta.recoveryRequired = false;

    saveMeta(meta);
}

function startCountdown() {
    if (countdownTimer) {
        clearInterval(countdownTimer);
    }

    countdownTimer = setInterval(() => {
        const meta = readMeta();

        if (!meta) {
            clearInterval(countdownTimer);
            return;
        }

        ensureFailureState(meta);

        const seconds = remainingLockSeconds(meta);

        if (seconds > 0) {
            setStatus(
                "Locked. Try again in " +
                seconds +
                " seconds."
            );
        } else if (countdownTimer) {
            clearInterval(countdownTimer);
            countdownTimer = null;
        }
    }, 250);
}


/* =========================
   VAULT SETUP
========================= */

async function createVault(event) {
    if (event) {
        event.preventDefault();
    }

    if (busy) {
        return;
    }

    const p1 = $("setupPassword1")?.value || "";
    const p2 = $("setupPassword2")?.value || "";
    const p3 = $("setupPassword3")?.value || "";
    const p4 = $("setupPassword4")?.value || "";

    if (
        p1.length < MIN_PASSWORD_LENGTH ||
        p3.length < MIN_PASSWORD_LENGTH
    ) {
        setStatus(
            "Both passwords must contain at least 12 characters."
        );
        return;
    }

    if (p1 !== p2) {
        setStatus(
            "The first password and its confirmation do not match."
        );
        return;
    }

    if (p3 !== p4) {
        setStatus(
            "The second password and its confirmation do not match."
        );
        return;
    }

    if (p1 === p3) {
        setStatus(
            "Choose two different passwords."
        );
        return;
    }

    busy = true;

    const button = $("createVaultBtn");

    if (button) {
        button.disabled = true;
    }

    try {
        setStatus(
            "Creating your encrypted vault. Please wait..."
        );

        const passwordSalt = randomBytes(16);
        const recoverySalt = randomBytes(16);
        const rawVaultKey = randomBytes(32);

        const wrappedVaultKey = await wrapVaultKey(
            p1,
            p3,
            passwordSalt,
            rawVaultKey
        );

        const recoveryCode = makeRecoveryCode();

        const recoveryKey = await deriveRecoveryKey(
            recoveryCode,
            recoverySalt
        );

        const wrappedRecoveryKey = await encryptBytes(
            recoveryKey,
            rawVaultKey
        );

        const meta = {
            version: 1,
            passwordSalt: toBase64(passwordSalt),
            recoverySalt: toBase64(recoverySalt),
            wrappedVaultKey,
            wrappedRecoveryKey,
            failures: 0,
            lockUntil: 0,
            recoveryRequired: false
        };

        saveMeta(meta);

        if ($("recoveryCodeOutput")) {
            $("recoveryCodeOutput").textContent =
                recoveryCode;
        }

        for (const id of [
            "setupPassword1",
            "setupPassword2",
            "setupPassword3",
            "setupPassword4"
        ]) {
            if ($(id)) {
                $(id).value = "";
            }
        }

        showScreen("recoveryDisplayScreen");

        setStatus(
            "Save this recovery code somewhere safe before continuing."
        );

    } catch (error) {
        console.error("Vault setup failed:", error);

        setStatus(
            "Vault creation failed. Check HTTPS, browser support and storage."
        );
    } finally {
        busy = false;

        if (button) {
            button.disabled = false;
        }
    }
}


/* =========================
   TWO-STEP UNLOCK
========================= */

function continueUnlock(event) {
    if (event) {
        event.preventDefault();
    }

    const meta = readMeta();

    if (!meta) {
        showScreen("setupScreen");
        return;
    }

    ensureFailureState(meta);

    if (meta.recoveryRequired) {
        showScreen("recoveryScreen");
        return;
    }

    const seconds = remainingLockSeconds(meta);

    if (seconds > 0) {
        setStatus(
            "Locked. Try again in " + seconds + " seconds."
        );
        return;
    }

    const p1 = $("password1")?.value || "";

    if (p1.length < MIN_PASSWORD_LENGTH) {
        setStatus(
            "Enter the first password (at least 12 characters)."
        );
        return;
    }

    firstPassword = p1;

    if ($("password1")) {
        $("password1").value = "";
    }

    showUnlockStep(2);
}

async function unlockVault(event) {
    if (event) {
        event.preventDefault();
    }

    if (busy) {
        return;
    }

    const meta = readMeta();

    if (!meta) {
        showScreen("setupScreen");
        return;
    }

    ensureFailureState(meta);

    if (meta.recoveryRequired) {
        showScreen("recoveryScreen");
        return;
    }

    const seconds = remainingLockSeconds(meta);

    if (seconds > 0) {
        setStatus(
            "Locked. Try again in " + seconds + " seconds."
        );
        return;
    }

    const p2 = $("password2")?.value || "";

    if (
        !firstPassword ||
        p2.length < MIN_PASSWORD_LENGTH
    ) {
        firstPassword = null;

        setStatus(
            "Enter both passwords. Each must contain at least 12 characters."
        );

        showUnlockStep(1);
        return;
    }

    busy = true;

    if ($("unlockBtn")) {
        $("unlockBtn").disabled = true;
    }

    try {
        setStatus(
            "Checking passwords. Please wait..."
        );

        // Only the combined password can unwrap the vault key.
        // The first password is not stored as a separate verifier.
        vaultKey = await unwrapVaultKey(
            firstPassword,
            p2,
            meta
        );

        firstPassword = null;

        if ($("password2")) {
            $("password2").value = "";
        }

        resetFailures();

        await renderGallery();

        showScreen("galleryScreen");

        startIdleTimer();

    } catch (error) {
        console.warn("Unlock failed.");

        vaultKey = null;
        firstPassword = null;

        if ($("password2")) {
            $("password2").value = "";
        }

        registerFailure();

    } finally {
        busy = false;

        if ($("unlockBtn")) {
            $("unlockBtn").disabled = false;
        }
    }
}


/* =========================
   RECOVERY
========================= */

async function recoverVault(event) {
    if (event) {
        event.preventDefault();
    }

    if (busy) {
        return;
    }

    const meta = readMeta();
    const code = $("recoveryInput")?.value.trim() || "";

    if (!meta || !code) {
        setStatus("Enter your recovery code.");
        return;
    }

    busy = true;

    if ($("recoverBtn")) {
        $("recoverBtn").disabled = true;
    }

    try {
        setStatus("Checking recovery code. Please wait...");

        const recoveryKey = await deriveRecoveryKey(
            code,
            fromBase64(meta.recoverySalt)
        );

        const rawVaultKey = await decryptBytes(
            recoveryKey,
            meta.wrappedRecoveryKey
        );

        vaultKey = await importAESKey(rawVaultKey);

        firstPassword = null;

        if ($("recoveryInput")) {
            $("recoveryInput").value = "";
        }

        resetFailures();

        await renderGallery();

        showScreen("galleryScreen");

        startIdleTimer();

    } catch (error) {
        console.warn("Recovery failed.");

        vaultKey = null;

        setStatus(
            "Invalid recovery code or damaged vault data."
        );
    } finally {
        busy = false;

        if ($("recoverBtn")) {
            $("recoverBtn").disabled = false;
        }
    }
}


/* =========================
   GALLERY
========================= */

function clearGalleryURLs() {
    for (const url of currentObjectURLs) {
        URL.revokeObjectURL(url);
    }

    currentObjectURLs = [];
}

function ensureAddMediaButton() {
    if ($("addMediaButton") || !$("fileInput")) {
        return;
    }

    const button = document.createElement("button");

    button.id = "addMediaButton";
    button.type = "button";
    button.textContent = "Add Photos / Videos";

    button.addEventListener("click", () => {
        if (vaultKey) {
            $("fileInput").click();
        }
    });

    $("galleryScreen").prepend(button);
}

async function addFiles(event) {
    const files = Array.from(event.target.files || []);

    // Allow choosing the same file again later.
    event.target.value = "";

    if (!vaultKey || files.length === 0) {
        return;
    }

    busy = true;

    try {
        setStatus("Encrypting selected media...");

        for (const file of files) {
            if (!vaultKey) {
                break;
            }

            const bytes = new Uint8Array(
                await file.arrayBuffer()
            );

            const encrypted = await encryptBytes(
                vaultKey,
                bytes
            );

            const id = toBase64(randomBytes(16));

            await dbPut({
                id,
                name: file.name,
                type: file.type || "application/octet-stream",
                size: file.size,
                iv: encrypted.iv,
                data: encrypted.data
            });
        }

        await renderGallery();

        setStatus("Selected media has been encrypted and saved.");

    } catch (error) {
        console.error("Adding media failed:", error);

        setStatus(
            "Unable to add media. Check browser storage and available space."
        );
    } finally {
        busy = false;
    }
}

async function renderGallery() {
    if (!vaultKey) {
        return;
    }

    const grid = $("galleryGrid");

    if (!grid) {
        return;
    }

    clearGalleryURLs();
    grid.replaceChildren();

    const items = await dbGetAll();
if ($("galleryEmpty")) {
        $("galleryEmpty").hidden = items.length !== 0;
    }

    for (const item of items) {
        const plainBytes = await decryptBytes(
            vaultKey,
            item
        );

        const blob = new Blob(
            [plainBytes],
            { type: item.type }
        );

        const url = URL.createObjectURL(blob);

        currentObjectURLs.push(url);

        const card = document.createElement("article");
        card.className = "gallery-item";

        let mediaElement;

        if (item.type.startsWith("image/")) {
            mediaElement = document.createElement("img");
            mediaElement.alt = item.name;
            mediaElement.loading = "lazy";
        } else if (item.type.startsWith("video/")) {
            mediaElement = document.createElement("video");
            mediaElement.controls = true;
            mediaElement.preload = "metadata";
        } else {
            mediaElement = document.createElement("a");
            mediaElement.textContent = "Open / Download file";
            mediaElement.download = item.name;
        }

        mediaElement.src = url;

        if (mediaElement.tagName === "A") {
            mediaElement.href = url;
        }

        card.appendChild(mediaElement);

        const name = document.createElement("p");
        name.className = "gallery-item-name";
        name.textContent = item.name;

        card.appendChild(name);

        const deleteButton = document.createElement("button");
        deleteButton.type = "button";
        deleteButton.textContent = "Delete";

        deleteButton.addEventListener("click", async () => {
            if (!vaultKey) {
                return;
            }

            if (!confirm("Permanently delete this item from the vault?")) {
                return;
            }

            try {
                await dbDelete(item.id);
                await renderGallery();
                setStatus("Item deleted.");
            } catch (error) {
                console.error(error);
                setStatus("Could not delete this item.");
            }
        });

        card.appendChild(deleteButton);
        grid.appendChild(card);
    }
}


/* =========================
   IDLE LOCK
========================= */

function stopIdleTimer() {
    if (idleTimer) {
        clearTimeout(idleTimer);
        idleTimer = null;
    }
}

function startIdleTimer() {
    stopIdleTimer();

    if (!vaultKey) {
        return;
    }

    idleTimer = setTimeout(() => {
        lockVault();
        setStatus("Vault locked after inactivity.");
    }, IDLE_MS);
}

function lockVault() {
    stopIdleTimer();

    vaultKey = null;
    firstPassword = null;

    clearGalleryURLs();

    if ($("galleryGrid")) {
        $("galleryGrid").replaceChildren();
    }

    for (const id of [
        "password1",
        "password2",
        "recoveryInput"
    ]) {
        if ($(id)) {
            $(id).value = "";
        }
    }

    const meta = readMeta();

    if (meta?.recoveryRequired) {
        showScreen("recoveryScreen");
    } else if (meta) {
        showUnlockStep(1);
    } else {
        showScreen("setupScreen");
    }
}


/* =========================
   DISABLE PASSWORD COPY/PASTE
========================= */

function disablePasswordClipboard() {
    const fields = document.querySelectorAll(
        'input[type="password"], #recoveryInput'
    );

    fields.forEach(field => {
        field.autocomplete = "new-password";
        field.autocapitalize = "off";
        field.spellcheck = false;

        for (const eventName of [
            "copy",
            "cut",
            "paste"
        ]) {
            field.addEventListener(eventName, event => {
                event.preventDefault();
            });
        }

        field.addEventListener("contextmenu", event => {
            event.preventDefault();
        });
    });
}


/* =========================
   INITIALIZATION
========================= */

function init() {
    if (!secureEnvironmentAvailable()) {
        showScreen("setupScreen");

        setStatus(
            "Use HTTPS on a supported browser to create the encrypted vault."
        );

        return;
    }

    if (
        typeof window.argon2 === "undefined" ||
        !window.argon2.ArgonType
    ) {
        showScreen("setupScreen");

        setStatus(
            "Argon2 library did not load. Check argon2.js."
        );

        return;
    }

    const meta = readMeta();

    if (!meta) {
        showScreen("setupScreen");
        return;
    }

    ensureFailureState(meta);
    saveMeta(meta);

    if (meta.recoveryRequired) {
        showScreen("recoveryScreen");
    } else {
        showUnlockStep(1);
        startCountdown();
    }

    ensureAddMediaButton();
}


/* =========================
   EVENT LISTENERS
========================= */

if ($("setupForm")) {
    $("setupForm").addEventListener(
        "submit",
        createVault
    );
}

if ($("unlockForm")) {
    $("unlockForm").addEventListener(
        "submit",
        unlockVault
    );
}

if ($("continueBtn")) {
    $("continueBtn").addEventListener(
        "click",
        continueUnlock
    );
}

if ($("backBtn")) {
    $("backBtn").addEventListener("click", () => {
        firstPassword = null;

        if ($("password2")) {
            $("password2").value = "";
        }

        showUnlockStep(1);
    });
}

if ($("recoveryForm")) {
    $("recoveryForm").addEventListener(
        "submit",
        recoverVault
    );
}

if ($("confirmRecoverySavedBtn")) {
    $("confirmRecoverySavedBtn").addEventListener(
        "click",
        () => {
            showUnlockStep(1);
        }
    );
}

if ($("fileInput")) {
    $("fileInput").addEventListener(
        "change",
        addFiles
    );
}

if ($("lockBtn")) {
    $("lockBtn").addEventListener(
        "click",
        lockVault
    );
}

[
    "pointerdown",
    "keydown",
    "touchstart"
].forEach(eventName => {
    window.addEventListener(
        eventName,
        () => {
            if (vaultKey) {
                startIdleTimer();
            }
        },
        { passive: true }
    );
});

document.addEventListener("visibilitychange", () => {
    if (document.hidden && vaultKey) {
        lockVault();
    }
});

disablePasswordClipboard();
init();