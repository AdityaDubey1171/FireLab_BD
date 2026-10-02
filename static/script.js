(function () {
    "use strict";

    /* ---- Expand / collapse: any .toggle or .more button inside a .card ---- */
    document.querySelectorAll(".toggle, .more").forEach(function (btn) {
        btn.addEventListener("click", function () {
            var card = btn.closest(".card");
            if (!card) { return; }
            var open = card.classList.toggle("open");
            card.querySelectorAll(":scope > .toggle, :scope > .more").forEach(function (b) {
                b.setAttribute("aria-expanded", open ? "true" : "false");
            });
        });
    });

    /* ---- Home simulator: animate the pipeline when checkRequest() runs ----
       Wraps the existing checkRequest() from script.js. It does not change it. */
    var flow = document.getElementById("sim-flow");
    var timers = [];

    function runFlow(type) {
        timers.forEach(clearTimeout);
        timers = [];
        flow.className = "mini-flow " + (type === "suspicious" ? "blocked" : "allowed");
        var items = Array.prototype.slice.call(flow.children);
        items.forEach(function (li) { li.classList.remove("on"); });
        items.forEach(function (li, i) {
            timers.push(setTimeout(function () { li.classList.add("on"); }, i * 180));
        });
    }

    if (flow && typeof window.checkRequest === "function") {
        var original = window.checkRequest;
        window.checkRequest = function (type) {
            var out = original.apply(this, arguments);
            runFlow(type);
            return out;
        };
    }
})();