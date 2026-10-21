"use strict";

/*
 * Private Gallery - Argon2id & AES-256-GCM
 * Secured: Combined password derivation (No separate split verifiers), 
 * Live 60s countdown timer, 10-attempt recovery trigger, camera lock fix, and secure sharing.
 */

const $ = (id) => document.getElementById(id);

const META_KEY = "private_gallery_argon2id_meta_v3";
const DB_NAME = "private_gallery_argon2id_db_v1";
const STORE_NAME = "media";

const MIN_PASSWORD_LENGTH = 12;

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
let isPickingFile = false;
let selectedItems = new Set();

/* =========================
   BASIC HELPERS
========================= */

function setStatus(message, isError = true) {
    const box = $("statusBox");
    if (!box) return;

    if (message) {
        box.textContent = message;
        box.hidden = false; 
        box.style.display = "block";
        box.style.borderColor = isError ? "#ff6b81" : "#8b5cf6";
        box.style.color = isError ? "#ffccd5" : "#f4f7ff";
    } else {
        box.textContent = "";
        box.hidden = true;
        box.style.display = "none";
    }
}

function showScreen(screenId, clearMessage = true) {
    const screenIds = ["setupScreen", "unlockScreen", "recoveryScreen", "recoveryDisplayScreen", "galleryScreen"];
    for (const id of screenIds) {
        const element = $(id);
        if (element) {
            const isTarget = (id === screenId);
            element.hidden = !isTarget;
            element.style.display = isTarget ? "" : "none";
        }
    }
    if (clearMessage) setStatus("");
    window.scrollTo({ top: 0, behavior: "instant" });
}

function showUnlockStep(stepNumber, clearMessage = true) {
    showScreen("unlockScreen", clearMessage);
    if ($("step1")) {
        $("step1").hidden = stepNumber !== 1;
        $("step1").style.display = stepNumber === 1 ? "" : "none";
    }
    if ($("step2")) {
        $("step2").hidden = stepNumber !== 2;
        $("step2").style.display = stepNumber === 2 ? "" : "none";
    }
}

function readMeta() {
    try {
        const value = localStorage.getItem(META_KEY);
        return value ? JSON.parse(value) : null;
    } catch { return null; }
}

function saveMeta(meta) {
    localStorage.setItem(META_KEY, JSON.stringify(meta));
}

function randomBytes(length) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
}

function toBase64(bytes) {
    let binary = "";
    for (const byte of bytes) { binary += String.fromCharCode(byte); }
    return btoa(binary);
}

function fromBase64(value) {
    const binary = atob(value);
    return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function makeRecoveryCode() {
    const bytes = randomBytes(32);
    return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
}

function secureEnvironmentAvailable() {
    return Boolean(window.crypto && crypto.subtle && window.indexedDB && window.isSecureContext);
}

/* =========================
   ARGON2ID & AES-256-GCM
========================= */

async function deriveArgonKey(password, saltBytes) {
    if (typeof window.argon2 === "undefined" || typeof window.argon2.hash !== "function") {
        throw new Error("Argon2 library is not loaded.");
    }
    const result = await window.argon2.hash({
        pass: password, salt: saltBytes, time: ARGON_TIME, mem: ARGON_MEMORY,
        hashLen: ARGON_HASH_LENGTH, parallelism: ARGON_PARALLELISM, type: window.argon2.ArgonType.Argon2id
    });
    return new Uint8Array(result.hash);
}

async function importAESKey(rawBytes) {
    return crypto.subtle.importKey("raw", rawBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function encryptBytes(key, bytes) {
    const iv = randomBytes(12);
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes);
    return { iv: toBase64(iv), data: toBase64(new Uint8Array(encrypted)) };
}

async function decryptBytes(key, record) {
    const iv = fromBase64(record.iv);
    const encrypted = fromBase64(record.data);
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encrypted);
    return new Uint8Array(decrypted);
}

async function wrapVaultKey(password1, password2, saltBytes, rawVaultKey) {
    const combinedPassword = password1 + "\u0000" + password2;
    const derivedBytes = await deriveArgonKey(combinedPassword, saltBytes);
    const wrappingKey = await importAESKey(derivedBytes);
    return encryptBytes(wrappingKey, rawVaultKey);
}

async function unwrapVaultKey(password1, password2, meta) {
    try {
        const combinedPassword = password1 + "\u0000" + password2;
        const derivedBytes = await deriveArgonKey(combinedPassword, fromBase64(meta.passwordSalt));
        const wrappingKey = await importAESKey(derivedBytes);
        const rawKey = await decryptBytes(wrappingKey, meta.wrappedVaultKey);
        return await importAESKey(rawKey);
    } catch (e) {
        throw new Error("Invalid password");
    }
}

async function deriveRecoveryKey(code, saltBytes) {
    const raw = await deriveArgonKey(code, saltBytes);
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
                db.createObjectStore(STORE_NAME, { keyPath: "id" });
            }
        };
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

async function dbPut(record) {
    const db = await openDatabase();
    return new Promise((resolve, reject) => {
        const transaction = db.transaction(STORE_NAME, "readwrite");
        transaction.objectStore(STORE_NAME).put(record);
        transaction.oncomplete = () => { db.close(); resolve(); };
        transaction.onerror = () => { db.close(); reject(transaction.error); };
    });
}

async function dbGetAll() {
    const db = await openDatabase();
    return new Promise((resolve, reject) => {
        const transaction = db.transaction(STORE_NAME, "readonly");
        const request = transaction.objectStore(STORE_NAME).getAll();
        request.onsuccess = () => { db.close(); resolve(request.result || []); };
        request.onerror = () => { db.close(); reject(request.error); };
    });
}

async function dbDelete(id) {
    const db = await openDatabase();
    return new Promise((resolve, reject) => {
        const transaction = db.transaction(STORE_NAME, "readwrite");
        transaction.objectStore(STORE_NAME).delete(id);
        transaction.oncomplete = () => { db.close(); resolve(); };
        transaction.onerror = () => { db.close(); reject(transaction.error); };
    });
}

/* =========================
   FAILURE COUNTERS & LIVE TIMER
========================= */

function ensureFailureState(meta) {
    if (!Number.isInteger(meta.failures)) meta.failures = 0;
    if (!Number.isFinite(meta.lockUntil)) meta.lockUntil = 0;
    if (typeof meta.recoveryRequired !== "boolean") meta.recoveryRequired = false;
}

function remainingLockSeconds(meta) {
    return Math.max(0, Math.ceil((meta.lockUntil - Date.now()) / 1000));
}

function setUnlockInputsDisabled(disabled) {
    if ($("continueBtn")) $("continueBtn").disabled = disabled;
    if ($("unlockBtn")) $("unlockBtn").disabled = disabled;
    if ($("backBtn")) $("backBtn").disabled = disabled;
    if ($("password1")) $("password1").disabled = disabled;
    if ($("password2")) $("password2").disabled = disabled;
}

function startCountdown() {
    if (countdownTimer) clearInterval(countdownTimer);

    const updateTimer = () => {
        const meta = readMeta();
        if (!meta) {
            clearInterval(countdownTimer);
            countdownTimer = null;
            return;
        }
        ensureFailureState(meta);
        const seconds = remainingLockSeconds(meta);

        if (seconds > 0) {
            setUnlockInputsDisabled(true);
            setStatus(`Too many failed attempts! Vault is locked for ${seconds} seconds.`, true);
        } else {
            clearInterval(countdownTimer);
            countdownTimer = null;
            if (meta.lockUntil !== 0) {
                meta.lockUntil = 0;
                saveMeta(meta);
            }
            setUnlockInputsDisabled(false);
            setStatus("Lock timer expired. You may try again now.", false);
        }
    };

    updateTimer(); 
    countdownTimer = setInterval(updateTimer, 250);
}

function registerFailure() {
    const meta = readMeta();
    if (!meta) return;

    ensureFailureState(meta);
    meta.failures += 1;

    if (meta.failures >= MAX_FAILURES) {
        meta.recoveryRequired = true;
        meta.lockUntil = 0;
        saveMeta(meta);
        firstPassword = null;
        if (countdownTimer) clearInterval(countdownTimer);
        setUnlockInputsDisabled(false);
        showScreen("recoveryScreen", false);
        setStatus("Maximum 10 failed attempts reached! Vault locked. Enter your Recovery Code to unlock.", true);
        return;
    }

    if (meta.failures % LOCK_EVERY === 0) {
        meta.lockUntil = Date.now() + LOCK_MS;
        saveMeta(meta);
        firstPassword = null;
        showUnlockStep(1, false);
        startCountdown();
        return;
    }

    saveMeta(meta);
    const remaining = MAX_FAILURES - meta.failures;
    const untilLock = LOCK_EVERY - (meta.failures % LOCK_EVERY);
    setStatus(`Incorrect password combination! (${untilLock} attempt(s) left before 60s lock, ${remaining} before Recovery Mode).`, true);
}

function resetFailures() {
    const meta = readMeta();
    if (!meta) return;
    meta.failures = 0;
    meta.lockUntil = 0;
    meta.recoveryRequired = false;
    saveMeta(meta);
}

/* =========================
   VAULT SETUP
========================= */

async function createVault(event) {
    if (event) event.preventDefault();
    if (busy) return;

    const p1 = $("setupPassword1")?.value || "";
    const p2 = $("setupPassword2")?.value || "";
    const p3 = $("setupPassword3")?.value || "";
    const p4 = $("setupPassword4")?.value || "";

    if (p1.length < MIN_PASSWORD_LENGTH) {
        setStatus(`First password must be at least ${MIN_PASSWORD_LENGTH} characters long.`, true);
        return;
    }
    if (p1 !== p2) { setStatus("First passwords do not match!", true); return; }
    if (p3.length < MIN_PASSWORD_LENGTH) {
        setStatus(`Second password must be at least ${MIN_PASSWORD_LENGTH} characters long.`, true);
        return;
    }
    if (p3 !== p4) { setStatus("Second passwords do not match!", true); return; }
    if (p1 === p3) { setStatus("First and Second passwords cannot be the same!", true); return; }

    busy = true;
    const button = $("createVaultBtn");
    if (button) button.disabled = true;

    try {
        setStatus("Creating your secure vault with Argon2id... Please wait.", false);
        const passwordSalt = randomBytes(16);
        const recoverySalt = randomBytes(16);
        const rawVaultKey = randomBytes(32);

        const wrappedVaultKey = await wrapVaultKey(p1, p3, passwordSalt, rawVaultKey);
        const recoveryCode = makeRecoveryCode();
        const recoveryKey = await deriveRecoveryKey(recoveryCode, recoverySalt);
        const wrappedRecoveryKey = await encryptBytes(recoveryKey, rawVaultKey);

        const meta = {
            version: 3,
            passwordSalt: toBase64(passwordSalt),
            recoverySalt: toBase64(recoverySalt),
            wrappedVaultKey,
            wrappedRecoveryKey,
            failures: 0,
            lockUntil: 0,
            recoveryRequired: false
        };

        saveMeta(meta);

        if ($("recoveryCodeOutput")) $("recoveryCodeOutput").textContent = recoveryCode;
        for (const id of ["setupPassword1", "setupPassword2", "setupPassword3", "setupPassword4"]) {
            if ($(id))$(id).value = "";
        }
        showScreen("recoveryDisplayScreen", false);
        setStatus("Vault created! Save your recovery code safely.", false);
    } catch (error) {
        console.error("Vault setup failed:", error);
        setStatus("Vault creation failed. Check browser support.", true);
    } finally {
        busy = false;
        if (button) button.disabled = false;
    }
}

/* =========================
   TWO-STEP UNLOCK
========================= */

function continueUnlock(event) {
    if (event) event.preventDefault();
    if (busy) return;

    const meta = readMeta();
    if (!meta) { showScreen("setupScreen"); return; }
    ensureFailureState(meta);

    if (meta.recoveryRequired) {
        showScreen("recoveryScreen", false);
        setStatus("Too many failed attempts. Enter your recovery code.", true);
        return;
    }

    const seconds = remainingLockSeconds(meta);
    if (seconds > 0) {
        startCountdown();
        return;
    }

    const p1 = $("password1")?.value || "";
    if (p1.length < MIN_PASSWORD_LENGTH) {
        setStatus(`First password must be at least ${MIN_PASSWORD_LENGTH} characters long.`, true);
        return;
    }

    firstPassword = p1;
    if ($("password1")) $("password1").value = "";
    showUnlockStep(2, false);
    setStatus("First password accepted. Now enter your Second password.", false);
}

async function unlockVault(event) {
    if (event) event.preventDefault();
    if (busy) return;

    const meta = readMeta();
    if (!meta) { showScreen("setupScreen"); return; }
    ensureFailureState(meta);

    if (meta.recoveryRequired) {
        showScreen("recoveryScreen", false);
        setStatus("Too many failed attempts. Enter your recovery code.", true);
        return;
    }

    const seconds = remainingLockSeconds(meta);
    if (seconds > 0) {
        startCountdown();
        return;
    }

    const p2 = $("password2")?.value || "";
    if (!firstPassword) {
        showUnlockStep(1, false);
        setStatus("Please enter your first password first.", true);
        return;
    }

    if (p2.length < MIN_PASSWORD_LENGTH) {
        setStatus(`Second password must be at least ${MIN_PASSWORD_LENGTH} characters long.`, true);
        return;
    }

    busy = true;
    if ($("unlockBtn")) $("unlockBtn").disabled = true;

    try {
        setStatus("Decrypting vault... Please wait.", false);
        vaultKey = await unwrapVaultKey(firstPassword, p2, meta);
        firstPassword = null;
        if ($("password2")) $("password2").value = "";

        resetFailures();
        await renderGallery();
        showScreen("galleryScreen", true);
        startIdleTimer();
    } catch (error) {
        console.warn("Unlock failed.");
        vaultKey = null;
        firstPassword = null;
        if ($("password2")) $("password2").value = "";
        showUnlockStep(1, false);
        registerFailure();
    } finally {
        busy = false;
        if ($("unlockBtn") && remainingLockSeconds(meta) === 0) {
            $("unlockBtn").disabled = false;
        }
    }
}

/* =========================
   RECOVERY
========================= */

async function recoverVault(event) {
    if (event) event.preventDefault();
    if (busy) return;

    const meta = readMeta();
    const code = $("recoveryInput")?.value.trim().toUpperCase() || "";

    if (!meta || !code) {
        setStatus("Please enter your recovery code.", true);
        return;
    }

    busy = true;
    if ($("recoverBtn")) $("recoverBtn").disabled = true;

    try {
        setStatus("Verifying recovery code...", false);
        const recoveryKey = await deriveRecoveryKey(code, fromBase64(meta.recoverySalt));
        const rawVaultKey = await decryptBytes(recoveryKey, meta.wrappedRecoveryKey);
        vaultKey = await importAESKey(rawVaultKey);
        firstPassword = null;
        if ($("recoveryInput")) $("recoveryInput").value = "";
        resetFailures();
        await renderGallery();
        showScreen("galleryScreen", false);
        setStatus("Vault recovered successfully!", false);
        startIdleTimer();
    } catch (error) {
        console.warn("Recovery failed.");
        vaultKey = null;
        setStatus("Invalid recovery code!", true);
    } finally {
        busy = false;
        if ($("recoverBtn")) $("recoverBtn").disabled = false;
    }
} 
/* =========================
   GALLERY & FILE HANDLING
========================= */

function clearGalleryURLs() {
    for (const url of currentObjectURLs) {
        URL.revokeObjectURL(url);
    }
    currentObjectURLs = [];
}

async function addFiles(event) {
    isPickingFile = false;
    const files = Array.from(event.target.files || []);
    event.target.value = "";

    if (!vaultKey || files.length === 0) return;
    busy = true;

    try {
        setStatus("Encrypting files securely...", false);
        for (const file of files) {
            if (!vaultKey) break;
            const bytes = new Uint8Array(await file.arrayBuffer());
            const encrypted = await encryptBytes(vaultKey, bytes);
            const id = toBase64(randomBytes(16));
            
            await dbPut({
                id,
                type: file.type || "application/octet-stream",
                size: file.size,
                iv: encrypted.iv,
                data: encrypted.data
            });
        }
        await renderGallery();
        setStatus("Files encrypted and saved successfully.", false);
    } catch (error) {
        console.error("Adding media failed:", error);
        setStatus("Unable to add media. Check storage space.", true);
    } finally {
        busy = false;
    }
}

async function renderGallery() {
    if (!vaultKey) return;
    const grid = $("galleryGrid");
    if (!grid) return;

    clearGalleryURLs();
    selectedItems.clear();
    grid.replaceChildren();

    const items = await dbGetAll();
    if ($("galleryEmpty")) $("galleryEmpty").hidden = items.length !== 0;

    let index = 1;
    for (const item of items) {
        const plainBytes = await decryptBytes(vaultKey, item);
        const blob = new Blob([plainBytes], { type: item.type });
        const url = URL.createObjectURL(blob);
        currentObjectURLs.push(url);

        const card = document.createElement("article");
        card.className = "gallery-item";
        card.style.position = "relative";

        let mediaElement;
        if (item.type.startsWith("image/")) {
            mediaElement = document.createElement("img");
            mediaElement.alt = "Private image";
            mediaElement.loading = "lazy";
        } else if (item.type.startsWith("video/")) {
            mediaElement = document.createElement("video");
            mediaElement.controls = true;
            mediaElement.preload = "metadata";
        } else {
            mediaElement = document.createElement("a");
            mediaElement.textContent = "Download file";
            mediaElement.download = "secure-file";
        }

        mediaElement.src = url;
        if (mediaElement.tagName === "A") mediaElement.href = url;

        card.appendChild(mediaElement);

        // शेयर करने के लिए चेकबॉक्स
        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.setAttribute("aria-label", "Select item to share");
        checkbox.style.cssText = "position: absolute; top: 10px; right: 10px; width: 22px; height: 22px; accent-color: var(--primary); cursor: pointer; z-index: 5;";
        checkbox.addEventListener("change", () => {
            if (checkbox.checked) {
                selectedItems.add(item.id);
            } else {
                selectedItems.delete(item.id);
            }
        });
        card.appendChild(checkbox);

        mediaElement.addEventListener("click", () => {
            openMediaModal(url, item.type);
        });

        const name = document.createElement("p");
        name.className = "gallery-item-name";
        name.textContent = `Media Item #${index++}`;
        card.appendChild(name);

        const deleteButton = document.createElement("button");
        deleteButton.type = "button";
        deleteButton.textContent = "Delete";

        deleteButton.addEventListener("click", async () => {
            if (!vaultKey) return;
            if (!confirm("Permanently delete this item?")) return;
            try {
                await dbDelete(item.id);
                await renderGallery();
                setStatus("Item deleted.", false);
            } catch (error) {
                console.error(error);
                setStatus("Could not delete this item.", true);
            }
        });

        card.appendChild(deleteButton);
        grid.appendChild(card);
    }
}

/* =========================
   SECURE FILE SHARING
========================= */

function getExtensionFromMime(mime) {
    if (!mime) return "";
    if (mime.includes("jpeg") || mime.includes("jpg")) return ".jpg";
    if (mime.includes("png")) return ".png";
    if (mime.includes("webp")) return ".webp";
    if (mime.includes("gif")) return ".gif";
    if (mime.includes("mp4")) return ".mp4";
    if (mime.includes("webm")) return ".webm";
    return "";
}

async function shareSelectedItems() {
    if (!vaultKey) return;

    if (selectedItems.size === 0) {
        setStatus("Please tick the checkbox on at least one photo/video to share.", true);
        return;
    }

    if (!navigator.share || !navigator.canShare) {
        setStatus("Direct sharing is not supported on this browser.", true);
        return;
    }

    try {
        setStatus("Preparing selected files for secure sharing...", false);
        const allItems = await dbGetAll();
        const filesToShare = [];

        let count = 1;
        for (const item of allItems) {
            if (selectedItems.has(item.id)) {
                const plainBytes = await decryptBytes(vaultKey, item);
                const ext = getExtensionFromMime(item.type);
                const file = new File([plainBytes], `private_media_${count++}${ext}`, {
                    type: item.type || "application/octet-stream"
                });
                filesToShare.push(file);
            }
        }

        if (navigator.canShare({ files: filesToShare })) {
            isPickingFile = true; // शेयर मेनू खुलते वक्त ऐप को बैकग्राउंड लॉक से बचाएगा
            await navigator.share({
                title: "Private Gallery",
                files: filesToShare
            });
            setStatus("Shared successfully.", false);
        } else {
            setStatus("Your device does not support sharing these file types.", true);
        }
    } catch (error) {
        if (error.name !== "AbortError") {
            console.error("Share failed:", error);
            setStatus("Unable to share selected media.", true);
        } else {
            setStatus("", false);
        }
    } finally {
        setTimeout(() => { isPickingFile = false; }, 1500);
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
    if (!vaultKey) return;
    idleTimer = setTimeout(() => {
        if (!isPickingFile) {
            lockVault();
            setStatus("Vault locked due to 60s of inactivity.", true);
        }
    }, IDLE_MS);
}

function lockVault() {
    stopIdleTimer();
    vaultKey = null;
    firstPassword = null;
    selectedItems.clear();
    clearGalleryURLs();

    if ($("galleryGrid")) $("galleryGrid").replaceChildren();
    for (const id of ["password1", "password2", "recoveryInput"]) {
        if ($(id))$(id).value = "";
    }

    const meta = readMeta();
    if (meta?.recoveryRequired) {
        showScreen("recoveryScreen", false);
    } else if (meta) {
        showUnlockStep(1, false);
    } else {
        showScreen("setupScreen", false);
    }
}

/* =========================
   DISABLE PASSWORD COPY/PASTE
========================= */

function disablePasswordClipboard() {
    const fields = document.querySelectorAll('input[type="password"]');
    fields.forEach(field => {
        field.autocomplete = "new-password";
        field.autocapitalize = "off";
        field.spellcheck = false;

        for (const eventName of ["copy", "cut", "paste"]) {
            field.addEventListener(eventName, event => {
                event.preventDefault();
                setStatus("Copy-paste is disabled on password fields for security.", true);
            });
        }
    });
}

/* =========================
   INITIALIZATION
========================= */

function init() {
    if (!secureEnvironmentAvailable()) {
        showScreen("setupScreen", false);
        setStatus("Use HTTPS on a supported browser.", true);
        return;
    }
    if (typeof window.argon2 === "undefined" || !window.argon2.ArgonType) {
        showScreen("setupScreen", false);
        setStatus("Argon2 library did not load.", true);
        return;
    }

    const meta = readMeta();
    if (!meta) {
        showScreen("setupScreen", true);
        return;
    }

    ensureFailureState(meta);
    saveMeta(meta);

    if (meta.recoveryRequired) {
        showScreen("recoveryScreen", false);
        setStatus("Too many failed attempts. Enter your recovery code.", true);
    } else {
        showUnlockStep(1, true);
        const seconds = remainingLockSeconds(meta);
        if (seconds > 0) {
            startCountdown();
        }
    }
}

/* =========================
   EVENT LISTENERS
========================= */

if ($("setupForm")) $("setupForm").addEventListener("submit", createVault);
if ($("unlockForm")) $("unlockForm").addEventListener("submit", unlockVault);
if ($("continueBtn")) $("continueBtn").addEventListener("click", continueUnlock);

if ($("password1")) {
    $("password1").addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
            e.preventDefault();
            continueUnlock(e);
        }
    });
}

if ($("backBtn")) {
    $("backBtn").addEventListener("click", () => {
        firstPassword = null;
        if ($("password2")) $("password2").value = "";
        showUnlockStep(1, true);
    });
}
if ($("recoveryForm")) $("recoveryForm").addEventListener("submit", recoverVault);
if ($("confirmRecoverySavedBtn")) {
    $("confirmRecoverySavedBtn").addEventListener("click", () => {
        showUnlockStep(1, true);
    });
}

if ($("addMediaLabel")) {
    $("addMediaLabel").addEventListener("pointerdown", () => { isPickingFile = true; });
    $("addMediaLabel").addEventListener("click", () => { isPickingFile = true; });
}
if ($("fileInput")) {
    $("fileInput").addEventListener("click", () => { isPickingFile = true; });
    $("fileInput").addEventListener("change", addFiles);
    $("fileInput").addEventListener("cancel", () => { isPickingFile = false; });
}

if ($("shareBtn")) $("shareBtn").addEventListener("click", shareSelectedItems);
if ($("lockBtn")) $("lockBtn").addEventListener("click", lockVault);

["pointerdown", "keydown", "touchstart"].forEach(eventName => {
    window.addEventListener(eventName, () => {
        if (vaultKey) startIdleTimer();
    }, { passive: true });
});

window.addEventListener("focus", () => {
    if (isPickingFile) {
        setTimeout(() => {
            isPickingFile = false;
            if (vaultKey) startIdleTimer();
        }, 1500);
    }
});

document.addEventListener("visibilitychange", () => {
    if (document.hidden && vaultKey) {
        if (!isPickingFile) {
            lockVault();
        }
    }
});

disablePasswordClipboard();

/* =====================================================
   FULL SCREEN MEDIA MODAL
===================================================== */
function openMediaModal(url, type) {
    const modal = $("mediaModal");
    if (!modal) return;

    modal.classList.remove("hidden");
    modal.style.display = "flex";

    const modalVideo = $("modalVideo");
    const modalImage = $("modalImage");

    if (typeof type === "string" && type.startsWith("video/")) {
        if (modalVideo) {
            modalVideo.src = url;
            modalVideo.classList.remove("hidden");
            modalVideo.style.display = "block";
            modalVideo.play();
        }
        if (modalImage) {
            modalImage.classList.add("hidden");
            modalImage.style.display = "none";
        }
    } else {
        if (modalImage) {
            modalImage.src = url;
            modalImage.classList.remove("hidden");
            modalImage.style.display = "block";
        }
        if (modalVideo) {
            modalVideo.classList.add("hidden");
            modalVideo.style.display = "none";
            modalVideo.pause();
            modalVideo.src = "";
        }
    }
}

const closeModalBtn = $("closeModal");
if (closeModalBtn) {
    closeModalBtn.addEventListener("click", () => {
        const modal = $("mediaModal");
        const modalVideo = $("modalVideo");
        const modalImage = $("modalImage");

        if (modal) {
            modal.classList.add("hidden");
            modal.style.display = "none";
        }
        if (modalVideo) {
            modalVideo.pause();
            modalVideo.src = "";
        }
        if (modalImage) {
            modalImage.src = "";
        }
    });
}

/* =====================================================
   PWA INSTALL & SERVICE WORKER
===================================================== */
let deferredPrompt;
const installAppBtn = document.getElementById("installAppBtn");

window.addEventListener("beforeinstallprompt", (e) => {
    e.preventDefault();
    deferredPrompt = e;
    if (installAppBtn) installAppBtn.style.display = "block";
});

if (installAppBtn) {
    installAppBtn.addEventListener("click", async () => {
        if (deferredPrompt) {
            deferredPrompt.prompt();
            await deferredPrompt.userChoice;
            deferredPrompt = null;
            installAppBtn.style.display = "none";
        }
    });
}

window.addEventListener("appinstalled", () => {
    if (installAppBtn) installAppBtn.style.display = "none";
});

if ("serviceWorker" in navigator) {
    window.addEventListener("load", () => {
        navigator.serviceWorker.register("./sw.js").catch(error => {
            console.warn("Service Worker registration failed:", error);
        });
    });
}

init();