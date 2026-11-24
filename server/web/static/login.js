// Login page for /authorize. The card token never leaves this origin except
// in the POST to /authorize/card, and is only held in memory here. A card
// scanned with a phone camera lands on /c, which hands the token over through
// sessionStorage; this page takes it out right away so that a login abandoned
// on a shared device leaves nothing for the next person in that tab.
"use strict";

(function () {
  const STORAGE_KEY = "cogin_card";
  const $ = (id) => document.getElementById(id);

  let token = "";
  let setupMode = false;
  let stream = null;
  let scanning = false;

  // HANDOFF_TTL_MS bounds how old a token handed over by /c may be. It only
  // has to survive the redirect through the client's login start.
  const HANDOFF_TTL_MS = 5 * 60 * 1000;

  function takeStored() {
    let raw = "";
    try {
      raw = sessionStorage.getItem(STORAGE_KEY) || "";
      sessionStorage.removeItem(STORAGE_KEY);
    } catch {
      return "";
    }
    try {
      const h = JSON.parse(raw);
      if (h && typeof h.token === "string" && Date.now() - h.at < HANDOFF_TTL_MS) {
        return h.token;
      }
    } catch {
      /* not a handoff record */
    }
    return "";
  }
  function clearStored() {
    try {
      sessionStorage.removeItem(STORAGE_KEY);
    } catch {
      /* storage unavailable: nothing to clear */
    }
  }

  // Accepts what a QR code or a typed code may contain: the card URL
  // (…/c#cgc_…) or the bare token.
  function extractToken(text) {
    const s = (text || "").trim();
    const i = s.indexOf("cgc_");
    if (i < 0) return "";
    return s.slice(i).split(/[\s&?#]/)[0];
  }

  function showMessage(text) {
    const el = $("message");
    el.textContent = text || "";
    el.hidden = !text;
  }

  function setToken(t) {
    token = t;
    setupMode = false;
    $("card-ready").hidden = !t;
    $("card-scan").hidden = !!t;
    $("step-pin").hidden = !t;
    $("pin-login").hidden = false;
    $("pin-setup").hidden = true;
    $("submit").textContent = "ログイン";
    if (t) {
      stopScan();
      setTimeout(() => $("pin").focus(), 0);
    }
  }

  function enterSetupMode() {
    setupMode = true;
    $("pin-login").hidden = true;
    $("pin-setup").hidden = false;
    $("submit").textContent = "PINを設定してログイン";
    setTimeout(() => $("new-pin").focus(), 0);
  }

  async function startScan() {
    showMessage("");
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      showMessage("このブラウザではカメラを使えません。「カメラが使えないとき」からコードを入力してください。");
      return;
    }
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: { ideal: "environment" } },
        audio: false,
      });
    } catch {
      showMessage("カメラを起動できませんでした。カメラの使用を許可するか、コードを入力してください。");
      return;
    }
    const video = $("video");
    video.srcObject = stream;
    await video.play();
    $("scanner").hidden = false;
    $("scan-start").hidden = true;
    scanning = true;
    scanLoop();
  }

  function stopScan() {
    scanning = false;
    if (stream) {
      stream.getTracks().forEach((t) => t.stop());
      stream = null;
    }
    $("scanner").hidden = true;
    $("scan-start").hidden = false;
  }

  // Native BarcodeDetector is used where available (faster); jsQR covers
  // browsers without it, which includes most desktop browsers on shared PCs.
  const detector =
    "BarcodeDetector" in window ? new window.BarcodeDetector({ formats: ["qr_code"] }) : null;

  async function decodeFrame(video) {
    if (detector) {
      try {
        const codes = await detector.detect(video);
        if (codes.length) return codes[0].rawValue;
        return "";
      } catch {
        /* fall through to jsQR */
      }
    }
    if (!window.jsQR || !video.videoWidth) return "";
    const canvas = $("canvas");
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const code = window.jsQR(img.data, img.width, img.height, { inversionAttempts: "dontInvert" });
    return code ? code.data : "";
  }

  async function scanLoop() {
    if (!scanning) return;
    const text = await decodeFrame($("video"));
    const t = extractToken(text);
    if (t) {
      setToken(t);
      return;
    }
    if (text) showMessage("ログインカードのQRコードではありません。");
    setTimeout(scanLoop, 200);
  }

  async function submit(e) {
    e.preventDefault();
    showMessage("");
    const body = { query: location.search.replace(/^\?/, ""), token: token };
    if (setupMode) {
      const p1 = $("new-pin").value;
      const p2 = $("new-pin2").value;
      if (p1 !== p2) {
        showMessage("2回入力したPINが一致しません。");
        return;
      }
      body.newPin = p1;
    } else {
      body.pin = $("pin").value;
    }
    $("submit").disabled = true;
    let res, data;
    try {
      res = await fetch("/authorize/card", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        credentials: "omit",
      });
      data = await res.json();
    } catch {
      $("submit").disabled = false;
      showMessage("通信に失敗しました。もう一度お試しください。");
      return;
    }
    $("submit").disabled = false;

    if (res.ok && data.redirect) {
      clearStored();
      $("pin").value = "";
      $("new-pin").value = "";
      $("new-pin2").value = "";
      location.replace(data.redirect);
      return;
    }
    $("pin").value = "";
    switch (data.error) {
      case "pin_setup_required":
        enterSetupMode();
        showMessage("");
        return;
      case "wrong_pin":
        showMessage("PINが違います（あと " + data.remaining + " 回間違えるとロックされます）");
        $("pin").focus();
        return;
      case "weak_pin":
        showMessage(data.message);
        return;
      case "locked":
      case "activation_expired":
      case "card_expired":
      case "invalid_card":
        clearStored();
        setToken("");
        showMessage(data.message);
        return;
      default:
        showMessage(data.message || "ログインできませんでした。");
    }
  }

  $("scan-start").addEventListener("click", startScan);
  $("scan-stop").addEventListener("click", stopScan);
  $("card-reset").addEventListener("click", () => {
    clearStored();
    setToken("");
    showMessage("");
  });
  $("manual-use").addEventListener("click", () => {
    const t = extractToken($("manual").value);
    $("manual").value = "";
    if (!t) {
      showMessage("コードの形式が正しくありません（cgc_ で始まるコードです）。");
      return;
    }
    showMessage("");
    setToken(t);
  });
  $("step-pin").addEventListener("submit", submit);
  window.addEventListener("pagehide", () => {
    stopScan();
    token = "";
  });

  setToken(takeStored());
})();
