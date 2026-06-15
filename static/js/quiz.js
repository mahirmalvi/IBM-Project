const QUIZ_QUESTIONS = [
    {
        question: "What does the 'https://' protocol at the start of a URL guarantee?",
        options: [
            "It guarantees the website is 100% legitimate and safe.",
            "It encrypts the connection, meaning hackers cannot read data in transit.",
            "It guarantees the site is free of viruses and malware.",
            "It prevents hackers from scanning your personal computer."
        ],
        correct: 1,
        explanation: "HTTPS encrypts the communication channel between your browser and the server. It does NOT guarantee that the site itself is safe; phishers can easily obtain free SSL certificates for their malicious domains."
    },
    {
        question: "If you get an email from 'service-paypal@security-alerts-update.com' asking to verify your account, what is the best indicator of phishing?",
        options: [
            "The email contains a PayPal logo.",
            "The sender's domain name 'security-alerts-update.com' does not match the official 'paypal.com'.",
            "The email has a link to verify your password.",
            "The email was sent during non-business hours."
        ],
        correct: 1,
        explanation: "Phishers use deceptive domains that look like official services, but the actual domain (the text after the '@' or in the main URL host) tells you where the email/site really originates. Official PayPal emails only come from domains ending in paypal.com."
    },
    {
        question: "What is URL shortening (e.g., bit.ly, tinyurl) commonly used for by scammers?",
        options: [
            "To hide the actual destination URL from the user and from basic email scanners.",
            "To make the webpage load faster on mobile devices.",
            "To bypass firewalls and download files automatically.",
            "To steal credit card numbers directly without a web form."
        ],
        correct: 0,
        explanation: "URL shorteners hide the destination URL, meaning the user cannot see where they will land until after they click. Always scan shortened URLs or use a link expander before visiting them."
    },
    {
        question: "What is a 'Prefix-Suffix' phishing trick in domain names?",
        options: [
            "Using numbers instead of letters (e.g., g00gle.com).",
            "Using hyphens to look like standard brands (e.g., netflix-billing.com).",
            "Adding '.html' at the end of the URL path.",
            "Using special characters like '@' inside the subdomain."
        ],
        correct: 1,
        explanation: "Phishers often register domains containing official brand names separated by hyphens (prefixes/suffixes) to make the domain look authentic to an untrained eye."
    },
    {
        question: "If a URL uses an IP address instead of a domain name (e.g., 'http://192.168.1.100/login.html'), why is it suspicious?",
        options: [
            "IP addresses cannot support SSL certificates.",
            "Legitimate organizations register friendly domain names, whereas IP-based URLs are usually unauthorized servers.",
            "Raw IP addresses load slower.",
            "It means the website is hosted on a dark web network."
        ],
        correct: 1,
        explanation: "Almost all legitimate businesses host their public services under a recognizable domain name. Raw IP addresses are used by attackers because registering domain names leaves a trace and takes time."
    },
    {
        question: "What is the security risk associated with the '@' symbol in a URL?",
        options: [
            "It automatically starts an executable file download.",
            "Browsers ignore everything before the '@' and load the domain that follows it.",
            "It highlights the username of the user.",
            "It represents an encrypted database connection."
        ],
        correct: 1,
        explanation: "In URL syntax, the part before the '@' is treated as credentials. Browsers will discard everything before '@' and direct you to the domain after the '@', which phishers exploit to mask spoof sites."
    },
    {
        question: "What does '2FA' stand for in cybersecurity?",
        options: [
            "Two-Factor Authentication.",
            "Two-Fold Authorization.",
            "Twin-File Access.",
            "Tertiary Firewall Alliance."
        ],
        correct: 0,
        explanation: "Two-Factor Authentication (2FA) adds a second layer of security (like an authenticator app code or SMS code) in addition to your password, making it much harder for phishers to compromise your account."
    },
    {
        question: "How does a Random Forest Classifier determine if a URL is phishing in our platform?",
        options: [
            "It downloads the webpage and scans for viruses.",
            "It checks a static blacklist of reported phishing sites.",
            "It combines predictions from multiple decision trees trained on extracted URL features.",
            "It tracks the physical location of the web server."
        ],
        correct: 2,
        explanation: "Our ML module extracts key features (like length, HTTP status, and subdomains) and inputs them into a Random Forest Classifier—an ensemble model composed of decision trees—to output a verdict."
    },
    {
        question: "Which of the following is NOT a typical keyword phishers use in URLs?",
        options: [
            "login",
            "verify",
            "secure",
            "recipe"
        ],
        correct: 3,
        explanation: "Keywords like 'login', 'verify', 'update', and 'secure' are used by phishers to create a sense of urgency or legitimacy. Common words like 'recipe' carry no standard credential verification triggers."
    },
    {
        question: "What is the best course of action if you suspect a website is a phishing page?",
        options: [
            "Type fake credentials to test if it accepts them.",
            "Close the browser tab immediately, report the link, and do not input any sensitive data.",
            "Click all links and buttons to find who owns the site.",
            "Forward the link to all your friends to warn them."
        ],
        correct: 1,
        explanation: "The safest option is to leave the page immediately. Do not type any details, as some sites capture keypresses in real-time. Report the URL to your browser provider or IT administrator."
    }
];

document.addEventListener("DOMContentLoaded", () => {
    let currentQuestionIdx = 0;
    let selectedOptionIdx = null;
    let userScore = 0;
    let isAnswered = false;

    // Elements
    const quizStartContainer = document.getElementById("quiz-start-container");
    const quizPlayContainer = document.getElementById("quiz-play-container");
    const quizResultContainer = document.getElementById("quiz-result-container");
    
    const startQuizBtn = document.getElementById("start-quiz-btn");
    const questionText = document.getElementById("quiz-question-text");
    const optionsContainer = document.getElementById("quiz-options-container");
    const progressText = document.getElementById("quiz-progress-text");
    const progressBar = document.getElementById("quiz-progress-bar");
    
    const submitAnswerBtn = document.getElementById("quiz-submit-btn");
    const nextQuestionBtn = document.getElementById("quiz-next-btn");
    const explanationContainer = document.getElementById("quiz-explanation-card");
    const explanationText = document.getElementById("quiz-explanation-text");
    
    const finalScoreText = document.getElementById("quiz-final-score");
    const saveQuizBtn = document.getElementById("quiz-save-btn");
    const quizSpinner = document.getElementById("quiz-spinner");

    // Event Listeners
    if (startQuizBtn) {
        startQuizBtn.addEventListener("click", () => {
            quizStartContainer.classList.add("d-none");
            quizPlayContainer.classList.remove("d-none");
            loadQuestion();
        });
    }

    if (submitAnswerBtn) {
        submitAnswerBtn.addEventListener("click", () => {
            if (selectedOptionIdx === null) {
                alert("Please select an option first!");
                return;
            }
            evaluateAnswer();
        });
    }

    if (nextQuestionBtn) {
        nextQuestionBtn.addEventListener("click", () => {
            currentQuestionIdx++;
            if (currentQuestionIdx < QUIZ_QUESTIONS.length) {
                loadQuestion();
            } else {
                showQuizResults();
            }
        });
    }

    if (saveQuizBtn) {
        saveQuizBtn.addEventListener("click", saveQuizResult);
    }

    // Load Question
    function loadQuestion() {
        isAnswered = false;
        selectedOptionIdx = null;
        
        const q = QUIZ_QUESTIONS[currentQuestionIdx];
        
        // Update texts
        questionText.textContent = q.question;
        progressText.textContent = `Question ${currentQuestionIdx + 1} of ${QUIZ_QUESTIONS.length}`;
        
        // Progress Bar
        const percent = ((currentQuestionIdx + 1) / QUIZ_QUESTIONS.length) * 100;
        progressBar.style.width = `${percent}%`;
        
        // Toggle buttons
        submitAnswerBtn.classList.remove("d-none");
        submitAnswerBtn.disabled = true;
        nextQuestionBtn.classList.add("d-none");
        explanationContainer.classList.add("d-none");
        
        // Generate options HTML
        optionsContainer.innerHTML = "";
        q.options.forEach((opt, idx) => {
            const btn = document.createElement("button");
            btn.className = "quiz-option-btn animate__animated animate__fadeInUp";
            btn.style.animationDelay = `${idx * 0.1}s`;
            btn.innerHTML = `<span class="badge-cs badge-primary me-2">${String.fromCharCode(65 + idx)}</span> ${opt}`;
            
            btn.addEventListener("click", () => {
                if (isAnswered) return;
                
                // Remove previous selected styling
                const allButtons = optionsContainer.querySelectorAll(".quiz-option-btn");
                allButtons.forEach(b => b.classList.remove("selected"));
                
                // Select this one
                btn.classList.add("selected");
                selectedOptionIdx = idx;
                submitAnswerBtn.disabled = false;
            });
            
            optionsContainer.appendChild(btn);
        });
    }

    // Evaluate Selected Answer
    function evaluateAnswer() {
        isAnswered = true;
        const q = QUIZ_QUESTIONS[currentQuestionIdx];
        const buttons = optionsContainer.querySelectorAll(".quiz-option-btn");
        
        submitAnswerBtn.classList.add("d-none");
        nextQuestionBtn.classList.remove("d-none");
        
        if (selectedOptionIdx === q.correct) {
            userScore++;
            buttons[selectedOptionIdx].classList.add("correct");
        } else {
            buttons[selectedOptionIdx].classList.add("wrong");
            buttons[q.correct].classList.add("correct");
        }
        
        // Show explanation
        explanationText.innerHTML = `<strong>Explanation:</strong> ${q.explanation}`;
        explanationContainer.classList.remove("d-none");
    }

    // Show Results Card
    function showQuizResults() {
        quizPlayContainer.classList.add("d-none");
        quizResultContainer.classList.remove("d-none");
        
        finalScoreText.textContent = `${userScore} / ${QUIZ_QUESTIONS.length}`;
        
        // Custom message based on score
        const resultMsg = document.getElementById("quiz-result-msg");
        if (userScore >= 8) {
            resultMsg.innerHTML = `<span class="text-success"><i class="bi bi-patch-check-fill"></i> Excellent!</span> You are a Phishing Awareness Expert. You qualify for a Certificate!`;
            saveQuizBtn.classList.remove("d-none");
        } else if (userScore >= 5) {
            resultMsg.innerHTML = `<span class="text-warning"><i class="bi bi-exclamation-triangle-fill"></i> Good Effort!</span> You passed, but we recommend scoring at least 8/10 to unlock your Certificate. Try again to boost your score!`;
            saveQuizBtn.classList.add("d-none"); // only >=8 gets certificate
        } else {
            resultMsg.innerHTML = `<span class="text-danger"><i class="bi bi-x-circle-fill"></i> Keep Learning!</span> Phishing attacks are sophisticated. Read our awareness articles and try the quiz again to qualify for the certificate.`;
            saveQuizBtn.classList.add("d-none");
        }
    }

    // Save Result to DB via Fetch
    async function saveQuizResult() {
        saveQuizBtn.disabled = true;
        quizSpinner.classList.remove("d-none");
        
        const csrfMeta = document.querySelector('meta[name="csrf-token"]');
        const csrfToken = csrfMeta ? csrfMeta.getAttribute("content") : "";
        
        try {
            const response = await fetch("/save-quiz", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": csrfToken
                },
                body: JSON.stringify({
                    score: userScore,
                    total: QUIZ_QUESTIONS.length
                })
            });
            
            const data = await response.json();
            
            if (response.ok && data.success) {
                // Redirect to certificate page
                window.location.href = `/certificate/${data.certificate_code}`;
            } else {
                alert("Error saving quiz: " + (data.error || "Please login to save progress and earn certificates."));
                saveQuizBtn.disabled = false;
            }
        } catch (err) {
            console.error("Save Quiz Error:", err);
            alert("Network error: Could not save quiz results.");
            saveQuizBtn.disabled = false;
        } finally {
            quizSpinner.classList.add("d-none");
        }
    }
});
