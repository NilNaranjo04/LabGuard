
document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll('input[type="password"]').forEach(function(input) {
    if (input.parentElement && input.parentElement.classList.contains("password-wrap")) return;
    const wrap = document.createElement("div");
    wrap.className = "password-wrap";
    wrap.style.position = "relative";
    wrap.style.display = "block";
    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(input);
    input.style.paddingRight = "42px";
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = "👁";
    btn.style.position = "absolute";
    btn.style.right = "10px";
    btn.style.top = "50%";
    btn.style.transform = "translateY(-50%)";
    btn.style.border = "none";
    btn.style.background = "transparent";
    btn.style.cursor = "pointer";
    btn.style.fontSize = "16px";
    btn.onclick = function () {
      input.type = input.type === "password" ? "text" : "password";
    };
    wrap.appendChild(btn);
  });
});
