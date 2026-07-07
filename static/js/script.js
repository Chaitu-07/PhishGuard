document.addEventListener("DOMContentLoaded", function () {

    const form = document.getElementById("scanForm");

    const loading = document.getElementById("loadingScreen");

    const loadingText = document.getElementById("loadingText");

    if (!form) return;

    form.addEventListener("submit", function () {

        loading.classList.add("active");

        const messages = [

            "Validating URL...",

            "Checking SSL Certificate...",

            "Retrieving WHOIS Information...",

            "Resolving DNS Records...",

            "Analyzing Website Structure...",

            "Calculating Risk Score...",

            "Generating Security Report..."

        ];

        let i = 0;

        loadingText.innerHTML = messages[0];

        const interval = setInterval(function(){

            i++;

            if(i < messages.length){

                loadingText.innerHTML = messages[i];

            }

        },600);

    });

});