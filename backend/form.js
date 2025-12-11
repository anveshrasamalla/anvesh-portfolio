/**
 * AEM → SFMC Form Submit Handler
 * Clean, production-ready, automatically handles new fields,
 * builds MessageBody, injects captcha token, and posts to servlet.
 */

(function ($) {

    let captchaReady = false;
    let sleepTimer = false;

    // -----------------------------------------
    // Helper: Get captcha token before submit
    // -----------------------------------------
    function getCaptchaKey() {
        grecaptcha.ready(function () {
            grecaptcha.execute(window.recaptchaSiteKey, { action: 'submit' }).then(function (token) {
                $("#g-recaptcha-response").val(token);
                captchaReady = true;
            });
        });
    }

    // Sleep prevention helper
    function resetSleepTimer() {
        sleepTimer = false;
    }

    // -----------------------------------------
    // Helper: Pad field names for readability
    // -----------------------------------------
    function pad(str, width) {
        str = str || "";
        while (str.length < width) str += " ";
        return str;
    }

    // -----------------------------------------
    // Build MessageBody by automatically looping
    // through every field in the form.
    //
    // This ensures future fields are automatically included.
    // -----------------------------------------
    function buildMessageBody($form) {
        let msg = "";
        const fields = $form.serializeArray();

        fields.forEach(function (field) {

            // Skip captcha token
            if (field.name === "g-recaptcha-response") return;

            // Skip SFMC special keys
            if (field.name === "formId" || field.name === "aemFormId") return;
            if (field.name === "data-extension-key") return;

            msg += pad(field.name + ":", 25) + field.value + "\n";
        });

        return msg;
    }

    // -----------------------------------------
    // Main submit handler
    // -----------------------------------------
    window.processSalesforceForm = function (e) {

        if (typeof e !== "undefined") e.preventDefault();

        // Wait for captcha if not ready
        if (captchaReady === false) {

            if (sleepTimer === true) return;

            sleepTimer = true;
            getCaptchaKey();
            return;
        }

        captchaReady = false;

        // Correct form selection
        const $form = $(".form-container");

        // Build message body dynamically
        const messageBody = buildMessageBody($form);
        $("#MessageBody").val(messageBody);

        // Build POST URL
        const url = window.location.origin + "/bin/wcm/sfmc";

        $.ajax({
            url: url,
            type: "POST",
            data: $form.serialize(),

            success: function (response) {
                if (response.error === false) {
                    showSuccess();
                    resetSleepTimer();
                    tealiumWithFormSuccess();
                } else {
                    showError();
                    resetSleepTimer();
                    tealiumWithFormFail();
                }
            },

            error: function (error) {
                console.error("SFMC AJAX error:", error);
                showError();
                tealiumWithFormFail();
            }
        });

    };

})(jQuery);
