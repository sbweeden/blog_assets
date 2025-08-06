// Update this from your Google recaptchav3 configuration
let siteKey = "YOUR_SITE_KEY";

window.addEventListener('load', function() {
  let pkmsloginFormsArray = Array.from(document.forms).filter((x) => x.action.endsWith('/pkmslogin.form'));
  if (pkmsloginFormsArray.length == 1) {
    // override what happens on pressing login form submit button to run recaptchav3 then submit form
    let submitButton = pkmsloginFormsArray[0].querySelector(".submitButton");
    if (submitButton != null) {
      submitButton.addEventListener("click", (e) => {
        e.preventDefault();
        grecaptcha.ready(function() {
          grecaptcha.execute(siteKey, {action: 'login'})
          .then((token) => {
            // Include token in hidden field in form submit
            let recaptchav3Token = document.createElement("input");
            recaptchav3Token.setAttribute("type", "hidden");
            recaptchav3Token.setAttribute("name", "recaptchav3Token");
            recaptchav3Token.setAttribute("value", token);
            let loginForm = Array.from(document.forms).filter((x) => x.action.endsWith('/pkmslogin.form'))[0];
            loginForm.appendChild(recaptchav3Token);
            loginForm.submit();
          }).catch((e) => {
            console.log("Got exception calling recaptchav3: " + e);
          });
        });
      });
    }
  }
});
