// Landing page for the URL in a card's QR code (/c#cgc_…), opened when the
// card is scanned with a phone's own camera app. It keeps the token in this
// tab's sessionStorage and sends the browser to the service's login start,
// which comes back to /authorize where login.js picks the token up.
"use strict";

(async function () {
  const msg = document.getElementById("message");
  const token = location.hash.replace(/^#/, "");
  // Drop the token from the address bar and history right away, so it is not
  // left behind in a shared browser.
  history.replaceState(null, "", location.pathname);

  if (!token.startsWith("cgc_")) {
    msg.textContent = "カードのQRコードを読み取り直してください。";
    return;
  }
  let res, data;
  try {
    res = await fetch("/card/resolve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: token }),
      credentials: "omit",
    });
    data = await res.json();
  } catch {
    msg.textContent = "通信に失敗しました。もう一度読み取ってください。";
    return;
  }
  if (!res.ok) {
    msg.textContent = data.message || "このカードは使えません。";
    return;
  }
  if (!data.initiateLoginUri) {
    msg.textContent = data.clientName + " のログイン画面を開き、「カードでログイン」からこのカードを読み取ってください。";
    return;
  }
  try {
    // Picked up (and removed) by the login page within a few minutes; see
    // HANDOFF_TTL_MS in login.js.
    sessionStorage.setItem("cogin_card", JSON.stringify({ token: token, at: Date.now() }));
  } catch {
    msg.textContent = "このブラウザではカードを一時保存できません。" + data.clientName + " のログイン画面から読み取ってください。";
    return;
  }
  msg.textContent = data.clientName + " のログインに進みます…";
  location.replace(data.initiateLoginUri);
})();
