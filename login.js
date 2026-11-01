document.addEventListener("DOMContentLoaded", () => {

    const loginForm = document.getElementById("loginForm");
    const usernameInput = document.getElementById("username");
    const passwordInput = document.getElementById("password");
    const showPassword = document.getElementById("togglePassword");
    const loginButton = document.getElementById("loginButton");
    const loginStatus = document.getElementById("loginStatus");


    // =========================================================
    // SHOW / HIDE PASSWORD
    // =========================================================

    if (showPassword && passwordInput) {

        showPassword.addEventListener("click", () => {

            if (passwordInput.type === "password") {

                passwordInput.type = "text";
                showPassword.textContent = "HIDE";

            } else {

                passwordInput.type = "password";
                showPassword.textContent = "SHOW";

            }

        });

    }


    // =========================================================
    // LOGIN FORM
    // =========================================================

    if (loginForm) {

        loginForm.addEventListener("submit", async (event) => {

            event.preventDefault();


            const username =
                usernameInput.value.trim();

            const password =
                passwordInput.value;


            // -------------------------------------------------
            // EMPTY FIELD CHECK
            // -------------------------------------------------

            if (!username || !password) {

                showStatus(
                    "ENTER OPERATOR ID AND SECURITY KEY",
                    "error"
                );

                return;

            }


            // -------------------------------------------------
            // BUTTON LOADING
            // -------------------------------------------------

            loginButton.disabled = true;

            loginButton.classList.add("loading");

            showStatus(
                "AUTHENTICATING OPERATOR...",
                "normal"
            );


            try {

                // -------------------------------------------------
                // SEND LOGIN REQUEST TO FLASK
                // -------------------------------------------------

                const response = await fetch("/api/login", {

                    method: "POST",

                    headers: {
                        "Content-Type": "application/json"
                    },

                    credentials: "same-origin",

                    body: JSON.stringify({
                        username: username,
                        password: password
                    })

                });


                const data = await response.json();


                // -------------------------------------------------
                // LOGIN SUCCESS
                // -------------------------------------------------

                if (response.ok && data.success) {

                    showStatus(
                        "ACCESS GRANTED — INITIALIZING SYSTEM...",
                        "success"
                    );


                    setTimeout(() => {

                        window.location.href = "/dashboard";

                    }, 800);


                }

                // -------------------------------------------------
                // LOGIN FAILED
                // -------------------------------------------------

                else {

                    showStatus(
                        "ACCESS DENIED — INVALID CREDENTIALS",
                        "error"
                    );

                    loginButton.disabled = false;

                    loginButton.classList.remove("loading");

                }


            } catch (error) {

                console.error("Login Error:", error);

                showStatus(
                    "SERVER CONNECTION ERROR",
                    "error"
                );

                loginButton.disabled = false;

                loginButton.classList.remove("loading");

            }

        });

    }


    // =========================================================
    // STATUS MESSAGE
    // =========================================================

    function showStatus(message, type) {

        if (!loginStatus) {
            return;
        }

        loginStatus.textContent = message;

        loginStatus.className = "login-status";


        if (type === "error") {

            loginStatus.classList.add("error");

        }


        if (type === "success") {

            loginStatus.classList.add("success");

        }

    }

});