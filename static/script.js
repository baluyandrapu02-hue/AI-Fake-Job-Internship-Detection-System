document.addEventListener("DOMContentLoaded", function () {

    // =========================
    // TEXTAREA CHARACTER COUNTER
    // =========================
    const textarea = document.getElementById("jobInput");
    const counter = document.getElementById("charCount");

    const samples = {
    fake: `Urgent hiring! Work from home data entry job. No experience needed. Earn Rs.50000 per month. Registration fee required to confirm slot. Contact through WhatsApp only. No interview required. Limited seats available.`,

    internship: `Get certified online internship now. Pay Rs.1999 training fee to confirm your seat. Certificate valid worldwide. Limited seats available. No interview or selection process required. Join Telegram group for details.`,

    fakeLink: `Urgent hiring for remote data entry job. No interview required. Instant joining available. Registration fee must be paid before confirmation. Apply using this link: https://quick-job-apply.example.com. Contact HR through WhatsApp only.`,

    internshipLink: `Online internship with guaranteed certificate. Training fee is mandatory to confirm your seat. No selection process required. Join Telegram group and apply here: https://internship-certificate.example.com. Limited seats available.`
};

    function updateCounter() {
        if (textarea && counter) {
            counter.textContent = textarea.value.length + " / 10000 characters";
        }
    }

    window.loadSample = function (type) {
        if (textarea && samples[type]) {
            textarea.value = samples[type];
            updateCounter();
            textarea.focus();
        }
    };

    if (textarea && counter) {
        textarea.addEventListener("input", updateCounter);
        updateCounter();
    }


    // =========================
    // LOADING MESSAGE + DISABLE ANALYZE BUTTON
    // =========================
    const scanForm = document.querySelector(".scan-box form");
    const scanButton = document.querySelector(".scan-btn");

    if (scanForm && scanButton) {
        scanForm.addEventListener("submit", function () {
            if (textarea && textarea.value.trim().length < 30) {
                return;
            }

            scanButton.disabled = true;
            scanButton.textContent = "Analyzing...";

            let loadingMessage = document.getElementById("loadingMessage");

            if (!loadingMessage) {
                loadingMessage = document.createElement("p");
                loadingMessage.id = "loadingMessage";
                loadingMessage.textContent = "Analyzing job/internship post, please wait...";
                loadingMessage.style.marginTop = "12px";
                loadingMessage.style.fontWeight = "600";
                loadingMessage.style.textAlign = "center";
                scanButton.insertAdjacentElement("afterend", loadingMessage);
            }
        });
    }


    // =========================
    // CONFIRM BEFORE DELETE
    // =========================
    const deleteLinks = document.querySelectorAll(
        'a[href^="/delete-scan"], a[href^="/delete-all-history"]'
    );

    deleteLinks.forEach(function (link) {
        link.addEventListener("click", function (event) {
            let message = "Are you sure you want to delete this scan?";

            if (link.getAttribute("href").includes("delete-all-history")) {
                message = "Are you sure you want to delete all scan history?";
            }

            const confirmed = confirm(message);

            if (!confirmed) {
                event.preventDefault();
            }
        });
    });


    // =========================
    // AUTO SCROLL TO RESULT CARD
    // =========================
    const resultCard = document.querySelector(".result-card");

    if (resultCard) {
        resultCard.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });
    }

});