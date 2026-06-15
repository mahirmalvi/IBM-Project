document.addEventListener("DOMContentLoaded", () => {
    // 1. Preloader Dynamic Boot Simulation (Ultra-Premium Scanner UI)
    const preloader = document.getElementById("preloader");
    const preloaderFill = document.querySelector(".preloader-fill-alt");
    const preloaderStatus = document.getElementById("preloader-status");

    if (preloader && preloaderFill && preloaderStatus) {
        const bootSteps = [
            { threshold: 12, text: "Initializing Security Kernel..." },
            { threshold: 35, text: "Loading Random Forest ML Models..." },
            { threshold: 60, text: "Constructing Heuristic Filters..." },
            { threshold: 82, text: "Synchronizing Encryption Shield..." },
            { threshold: 100, text: "CyberShield Core Online. Launching." }
        ];

        let progress = 0;
        let stepIdx = 0;

        const updateBootLoader = () => {
            // Organic random loading speed increments
            progress += Math.floor(Math.random() * 8) + 4;
            if (progress > 100) progress = 100;

            preloaderFill.style.width = `${progress}%`;

            // Check text threshold state
            if (stepIdx < bootSteps.length && progress >= bootSteps[stepIdx].threshold) {
                preloaderStatus.textContent = bootSteps[stepIdx].text;
                stepIdx++;
            }

            if (progress < 100) {
                setTimeout(updateBootLoader, 50 + Math.random() * 35);
            } else {
                // Short organic pause on completion, then fadeout
                setTimeout(() => {
                    preloader.classList.add("hidden");
                    animateCounters();
                }, 350);
            }
        };

        // Start simulated boot sequence
        setTimeout(updateBootLoader, 100);
    } else if (preloader) {
        // Simple fallback
        window.addEventListener("load", () => {
            setTimeout(() => {
                preloader.classList.add("hidden");
                animateCounters();
            }, 800);
        });
    }

    // 2. AOS & GSAP Animations Initialization
    if (typeof AOS !== 'undefined') {
        AOS.init({
            duration: 800,
            easing: 'ease-out-cubic',
            once: true,
            mirror: false
        });
    }

    // GSAP ScrollTrigger Effects on Cards (Anti-CLS: transform and opacity only)
    if (typeof gsap !== 'undefined') {
        gsap.registerPlugin(ScrollTrigger);
        gsap.from(".glass-card, .stat-card", {
            scrollTrigger: {
                trigger: ".glass-card, .stat-card",
                start: "top 90%",
                toggleActions: "play none none none"
            },
            y: 30,
            opacity: 0,
            duration: 0.6,
            stagger: 0.1,
            ease: "power2.out",
            clearProps: "transform,opacity"
        });
    }

    // 3. Theme Switcher Logic
    const themeToggleBtn = document.getElementById("theme-toggle");
    const currentTheme = localStorage.getItem("theme") || "dark";

    document.documentElement.setAttribute("data-theme", currentTheme);
    updateThemeIcon(currentTheme);

    if (themeToggleBtn) {
        themeToggleBtn.addEventListener("click", () => {
            let theme = document.documentElement.getAttribute("data-theme");
            let newTheme = theme === "light" ? "dark" : "light";

            document.documentElement.setAttribute("data-theme", newTheme);
            localStorage.setItem("theme", newTheme);
            updateThemeIcon(newTheme);

            // Re-render particle network colors if canvas exists
            if (window.resizeCanvas) {
                window.setupParticles();
            }
        });
    }

    function updateThemeIcon(theme) {
        if (!themeToggleBtn) return;
        const icon = themeToggleBtn.querySelector("i");
        if (!icon) return;

        if (theme === "dark") {
            icon.className = "bi bi-sun-fill";
            themeToggleBtn.title = "Switch to Light Mode";
        } else {
            icon.className = "bi bi-moon-stars-fill";
            themeToggleBtn.title = "Switch to Dark Mode";
        }
    }

    // 4. HTML5 Canvas 3D Rotating wireframe Globe (Premium Interactive wall theme)
    const canvas = document.getElementById("particles-canvas");
    if (canvas) {
        const ctx = canvas.getContext("2d");
        let points = [];
        let connections = [];
        let spaceParticles = [];
        let angleX = 0.35; // Initial tilt angle
        let angleY = 0;    // Auto rotation angle
        let mouseXOffset = 0;
        let mouseYOffset = 0;
        let targetMouseX = 0;
        let targetMouseY = 0;

        // Listen for mousemove to handle parallax tilts
        document.addEventListener("mousemove", (e) => {
            targetMouseX = ((e.clientX - window.innerWidth / 2) / (window.innerWidth / 2)) * 0.45;
            targetMouseY = ((e.clientY - window.innerHeight / 2) / (window.innerHeight / 2)) * 0.45;
        });

        window.setupParticles = () => {
            points = [];
            connections = [];
            spaceParticles = [];

            const isDark = document.documentElement.getAttribute("data-theme") === "dark";

            // Calculate dynamic radius based on screen width/height
            let radius = Math.min(canvas.width, canvas.height) * 0.26;
            if (radius > 230) radius = 230;
            if (radius < 120) radius = 120;

            const numLat = 9;
            const numLon = 18;

            // 1. Generate 3D grid points for the sphere
            for (let i = 1; i < numLat; i++) {
                const phi = (Math.PI * i) / numLat;
                for (let j = 0; j < numLon; j++) {
                    const theta = (2 * Math.PI * j) / numLon;
                    const x = radius * Math.sin(phi) * Math.cos(theta);
                    const y = radius * Math.cos(phi);
                    const z = radius * Math.sin(phi) * Math.sin(theta);
                    points.push({ x, y, z });
                }
            }

            // 2. Generate connections grid indices
            for (let i = 0; i < numLat - 1; i++) {
                for (let j = 0; j < numLon; j++) {
                    const curr = i * numLon + j;

                    // Horizontal loop connection (latitudinal ring)
                    const nextHor = i * numLon + ((j + 1) % numLon);
                    connections.push([curr, nextHor]);

                    // Vertical connection (longitudinal meridian)
                    if (i < numLat - 2) {
                        const nextVert = (i + 1) * numLon + j;
                        connections.push([curr, nextVert]);
                    }
                }
            }

            // 3. Generate slow background drift space particles
            const numSpaceParticles = 35;
            const particleColor = isDark ? "rgba(0, 200, 255, 0.25)" : "rgba(0, 87, 255, 0.12)";
            for (let i = 0; i < numSpaceParticles; i++) {
                spaceParticles.push({
                    x: Math.random() * canvas.width,
                    y: Math.random() * canvas.height,
                    vx: (Math.random() - 0.5) * 0.3,
                    vy: (Math.random() - 0.5) * 0.3,
                    radius: Math.random() * 2 + 1,
                    color: particleColor
                });
            }
        };

        window.resizeCanvas = () => {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
            window.setupParticles();
        };

        window.addEventListener("resize", window.resizeCanvas);
        window.resizeCanvas();

        const drawParticles = () => {
            ctx.clearRect(0, 0, canvas.width, canvas.height);

            const isDark = document.documentElement.getAttribute("data-theme") === "dark";

            // Advance auto rotation
            angleY += 0.002;
            angleX += 0.0001;

            // Smoothly ease target offsets
            mouseXOffset += (targetMouseX - mouseXOffset) * 0.06;
            mouseYOffset += (targetMouseY - mouseYOffset) * 0.06;

            const currentAngleY = angleY + mouseXOffset;
            const currentAngleX = angleX + mouseYOffset;

            const cosX = Math.cos(currentAngleX);
            const sinX = Math.sin(currentAngleX);
            const cosY = Math.cos(currentAngleY);
            const sinY = Math.sin(currentAngleY);

            // Center coordinates of viewport
            const centerX = canvas.width / 2;
            // Place it slightly higher on desktop, centered behind hero text
            const centerY = canvas.height * 0.40;
            const perspective = 500;

            // Render background stars / drifting particles
            spaceParticles.forEach(p => {
                p.x += p.vx;
                p.y += p.vy;

                if (p.x < 0) p.x = canvas.width;
                if (p.x > canvas.width) p.x = 0;
                if (p.y < 0) p.y = canvas.height;
                if (p.y > canvas.height) p.y = 0;

                ctx.beginPath();
                ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
                ctx.fillStyle = p.color;
                ctx.fill();
            });

            // Project 3D points
            let radiusVal = Math.min(canvas.width, canvas.height) * 0.26;
            if (radiusVal > 230) radiusVal = 230;
            if (radiusVal < 120) radiusVal = 120;

            const projectedPoints = points.map(p => {
                // Y rotation
                let x1 = p.x * cosY - p.z * sinY;
                let z1 = p.x * sinY + p.z * cosY;

                // X rotation
                let y2 = p.y * cosX - z1 * sinX;
                let z2 = p.y * sinX + z1 * cosX;

                // Projection scaling
                const scale = perspective / (perspective + z2);
                const projX = centerX + x1 * scale;
                const projY = centerY + y2 * scale;

                return {
                    x: projX,
                    y: projY,
                    z: z2,
                    scale: scale
                };
            });

            // Draw wireframe connection lines (ordered by depth to draw back first, or shaded)
            connections.forEach(conn => {
                const pA = projectedPoints[conn[0]];
                const pB = projectedPoints[conn[1]];

                const avgZ = (pA.z + pB.z) / 2;
                const t = (avgZ + radiusVal) / (2 * radiusVal); // 0 (front) to 1 (back)

                const opacity = isDark
                    ? (1 - t) * 0.22 + 0.05
                    : (1 - t) * 0.14 + 0.03;

                const strokeStyle = isDark
                    ? `rgba(0, 200, 255, ${opacity})`
                    : `rgba(0, 87, 255, ${opacity})`;

                ctx.beginPath();
                ctx.moveTo(pA.x, pA.y);
                ctx.lineTo(pB.x, pB.y);
                ctx.strokeStyle = strokeStyle;
                ctx.lineWidth = isDark ? (1 - t) * 0.8 + 0.35 : (1 - t) * 0.6 + 0.2;
                ctx.stroke();
            });

            // Draw points
            projectedPoints.forEach(p => {
                const t = (p.z + radiusVal) / (2 * radiusVal);
                const opacity = isDark
                    ? (1 - t) * 0.55 + 0.15
                    : (1 - t) * 0.38 + 0.06;

                const dotRadius = isDark
                    ? (1 - t) * 2.8 + 0.8
                    : (1 - t) * 2.0 + 0.6;

                const fillStyle = isDark
                    ? `rgba(0, 255, 157, ${opacity})` // vibrant neon green in dark mode
                    : `rgba(0, 87, 255, ${opacity})`;

                ctx.beginPath();
                ctx.arc(p.x, p.y, dotRadius, 0, Math.PI * 2);
                ctx.fillStyle = fillStyle;
                ctx.fill();
            });

            requestAnimationFrame(drawParticles);
        };
        drawParticles();
    }

    // 5. Typing Text Typewriter Effect
    const typeElement = document.getElementById("typing-text");
    if (typeElement) {
        const words = JSON.parse(typeElement.getAttribute("data-words") || "[]");
        let wordIndex = 0;
        let charIndex = 0;
        let isDeleting = false;
        let typeSpeed = 100;

        const type = () => {
            const currentWord = words[wordIndex];
            if (isDeleting) {
                typeElement.textContent = currentWord.substring(0, charIndex - 1);
                charIndex--;
                typeSpeed = 40; // delete faster
            } else {
                typeElement.textContent = currentWord.substring(0, charIndex + 1);
                charIndex++;
                typeSpeed = 100;
            }

            if (!isDeleting && charIndex === currentWord.length) {
                isDeleting = true;
                typeSpeed = 2000; // Pause at full word
            } else if (isDeleting && charIndex === 0) {
                isDeleting = false;
                wordIndex = (wordIndex + 1) % words.length;
                typeSpeed = 500; // Pause before typing next word
            }

            setTimeout(type, typeSpeed);
        };
        setTimeout(type, 1000);
    }

    // 6. Smooth Scrolling for anchors
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            const hrefVal = this.getAttribute('href');
            if (hrefVal === "#") return;
            const target = document.querySelector(hrefVal);
            if (target) {
                e.preventDefault();
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // 7. Auto-dismiss Flash Messages
    const flashAlerts = document.querySelectorAll(".alert-dismissible");
    flashAlerts.forEach(alert => {
        setTimeout(() => {
            const closeBtn = alert.querySelector(".btn-close");
            if (closeBtn) {
                closeBtn.click();
            }
        }, 5000);
    });

    // 8. Stats Counters Auto-increment (GSAP ScrollTrigger optimized with dynamic viewport threshold)
    function animateCounters() {
        const counters = document.querySelectorAll(".counter-number");
        if (typeof gsap !== 'undefined' && typeof ScrollTrigger !== 'undefined') {
            counters.forEach(counter => {
                const targetVal = +counter.getAttribute("data-target");
                const obj = { val: 0 };
                gsap.to(obj, {
                    val: targetVal,
                    duration: 1.5,
                    ease: "power2.out",
                    scrollTrigger: {
                        trigger: counter,
                        start: "top 90%",
                        toggleActions: "play none none none"
                    },
                    onUpdate: () => {
                        counter.textContent = Math.floor(obj.val);
                    },
                    onComplete: () => {
                        counter.textContent = targetVal;
                    }
                });
            });
        } else {
            counters.forEach(counter => {
                const target = +counter.getAttribute("data-target");
                const duration = 1500; // 1.5s animation
                const startTime = performance.now();

                const updateCount = (currentTime) => {
                    const elapsedTime = currentTime - startTime;
                    const progress = Math.min(elapsedTime / duration, 1);

                    // Ease out cubic
                    const easeProgress = 1 - Math.pow(1 - progress, 3);

                    const currentValue = Math.floor(easeProgress * target);
                    counter.textContent = currentValue;

                    if (progress < 1) {
                        requestAnimationFrame(updateCount);
                    } else {
                        counter.textContent = target;
                    }
                };

                requestAnimationFrame(updateCount);
            });
        }
    }

    // 9. Scroll Progress Indicator Logic
    const scrollProgress = document.getElementById("scroll-progress");
    if (scrollProgress) {
        window.addEventListener("scroll", () => {
            const height = document.documentElement.scrollHeight - document.documentElement.clientHeight;
            const scrolled = height > 0 ? (window.scrollY / height) * 100 : 0;
            scrollProgress.style.width = `${scrolled}%`;
        });
    }

    // 10. Custom Cursor Follow Logic
    const cursor = document.getElementById("custom-cursor");
    if (cursor) {
        document.addEventListener("mousemove", (e) => {
            cursor.style.left = `${e.clientX}px`;
            cursor.style.top = `${e.clientY}px`;
        });
        document.addEventListener("mousedown", () => {
            cursor.style.transform = "translate(-50%, -50%) scale(0.8)";
        });
        document.addEventListener("mouseup", () => {
            cursor.style.transform = "translate(-50%, -50%) scale(1)";
        });

        // Add hover triggers
        const hoverables = "a, button, input, select, textarea, .quiz-option-btn, .sidebar-link, .dropdown-item";
        document.body.addEventListener("mouseenter", (e) => {
            if (e.target.matches && e.target.matches(hoverables)) {
                cursor.classList.add("cursor-hover");
            }
        }, true);
        document.body.addEventListener("mouseleave", (e) => {
            if (e.target.matches && e.target.matches(hoverables)) {
                cursor.classList.remove("cursor-hover");
            }
        }, true);
    }

    // 11. Sticky Navbar Shrink Logic
    const navbar = document.querySelector(".navbar-cybershield");
    if (navbar) {
        window.addEventListener("scroll", () => {
            if (window.scrollY > 40) {
                navbar.classList.add("scrolled");
            } else {
                navbar.classList.remove("scrolled");
            }
        });
    }

    // 12. Mouse Parallax on Hero Visuals
    const parallaxContainers = document.querySelectorAll(".hero-section, .about-hero-section");
    parallaxContainers.forEach(container => {
        const elements = container.querySelectorAll(".hero-visual-card, .hero-glow");
        container.addEventListener("mousemove", (e) => {
            const width = container.offsetWidth;
            const height = container.offsetHeight;
            const mouseX = e.clientX - container.offsetLeft - width / 2;
            const mouseY = e.clientY - container.offsetTop - height / 2;

            elements.forEach(el => {
                const depth = el.classList.contains("hero-glow") ? 0.03 : 0.015;
                const moveX = mouseX * depth;
                const moveY = mouseY * depth;
                // Use translate only for performance and to avoid layout shift
                if (el.classList.contains("hero-glow")) {
                    el.style.transform = `translate(${moveX}px, ${moveY}px)`;
                } else {
                    el.style.transform = `translate(${moveX}px, ${moveY}px) rotateX(${-moveY * 0.05}deg) rotateY(${moveX * 0.05}deg)`;
                }
            });
        });
    });

    // 13. Smooth Scroll to Hash target on page load (e.g. from dropdown navigation)
    if (window.location.hash) {
        const hash = window.location.hash;
        // Wait for preloader to hide (takes 1.0s boot simulation + transitions)
        setTimeout(() => {
            const target = document.querySelector(hash);
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        }, 1200);
    }
    // 14. Scroll to Top Button Logic
    const scrollToTopBtn = document.getElementById("scrollToTopBtn");
    if (scrollToTopBtn) {
        window.addEventListener("scroll", () => {
            if (window.scrollY > 300) {
                scrollToTopBtn.style.display = "flex";
            } else {
                scrollToTopBtn.style.display = "none";
            }
        });
        scrollToTopBtn.addEventListener("click", () => {
            window.scrollTo({
                top: 0,
                behavior: "smooth"
            });
        });
    }

    // 15. Desktop Sidebar Toggle Logic
    const desktopSidebarToggle = document.getElementById("desktopSidebarToggle");
    if (desktopSidebarToggle) {
        desktopSidebarToggle.addEventListener("click", () => {
            const sidebar = document.querySelector(".sidebar-cs");
            if (sidebar) {
                sidebar.classList.toggle("sidebar-collapsed");
            }
        });
    }
});